use std::{
    collections::BTreeMap,
    ffi::c_int,
    time::{Duration, SystemTime},
};

use crate::{
    enc_reader::{self, CbcCache},
    manifestdb::{self, FileType},
};
use aes::Aes256;
use aes_kw::Kek;
use fuser::FileAttr;
use rusqlite::{CachedStatement, Connection};
use sha1::Digest;

const ENOENT: c_int = 2;
const EIO: c_int = 5;
const E2BIG: c_int = 7;
const ENOTDIR: c_int = 20;
const ERANGE: c_int = 34;
const ENOSYS: c_int = 38;
const ENODATA: c_int = 61;
pub(crate) struct BackupFS<'db> {
    fs: crate::manifestdb::FS,
    con: &'db rusqlite::Connection,
    keys: BTreeMap<u32, Kek<Aes256>>,
    basepath: std::path::PathBuf,
    options: Options,
}

struct Options {
    verify_digests: bool,
}

impl<'con> BackupFS<'con> {
    pub(crate) fn new(
        fs: crate::manifestdb::FS,
        con: &'con Connection,
        keys: BTreeMap<u32, Kek<Aes256>>,
        basepath: std::path::PathBuf,
    ) -> Self {
        con.prepare_cached("SELECT file FROM Files WHERE fileID = ?")
            .unwrap();
        Self {
            fs,
            con,
            keys,
            basepath,
            options: Options {
                verify_digests: true,
            },
        }
    }

    fn get_statement(&self) -> CachedStatement<'_> {
        self.con
            .prepare_cached("SELECT file FROM Files WHERE fileID = ?")
            .unwrap()
    }

    fn get_mbfile(&self, inode_id: &manifestdb::RawId) -> manifestdb::MBFile {
        self.get_statement()
            .query_row([inode_id.as_stringid().as_str()], |r| {
                Ok(r.get::<_, manifestdb::MBFile>(0).unwrap())
            })
            .unwrap()
    }

    fn file_attr(&self, ino: usize) -> FileAttr {
        let inode = &self.fs.backing[ino];
        let m = if ino > 1 {
            let m = self.get_mbfile(&inode.id);
            Some(m)
        } else {
            None
        };

        let size: u64 = match inode.ftype {
            FileType::File => m.as_ref().map(|z| z.size).unwrap_or(0),
            FileType::Folder => inode.children.as_ref().unwrap().len() as u64,
        };

        let kind = inode.ftype.into();

        let crtime = m
            .as_ref()
            .map(|z| SystemTime::UNIX_EPOCH + Duration::from_secs(z.birth))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let ctime = m
            .as_ref()
            .map(|z| SystemTime::UNIX_EPOCH + Duration::from_secs(z.last_status_change))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mtime = m
            .as_ref()
            .map(|z| SystemTime::UNIX_EPOCH + Duration::from_secs(z.last_modified))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let atime = std::cmp::max(crtime, std::cmp::max(ctime, mtime));
        //        let perm = m.as_ref().map(|z| z.Mode).unwrap_or(0) as u16;
        let flags = m.as_ref().map(|z| z.flags).unwrap_or(0) as u32;
        let uid = m.as_ref().map(|z| z.user_i_d).unwrap_or(0) as u32;
        let gid = m.as_ref().map(|z| z.group_i_d).unwrap_or(0) as u32;

        FileAttr {
            ino: ino as u64,
            blksize: 4096,
            size,
            blocks: 0,
            atime,
            mtime,
            ctime,
            crtime,
            kind,
            perm: 0x1ff,
            nlink: 0,
            uid,
            gid,
            rdev: 0,
            flags,
        }
    }
}

struct OpenFile {
    encrypted_size: u64,
    zero_size: u64,
    f: std::fs::File,
    cbc_cache: CbcCache,
}

impl fuser::Filesystem for BackupFS<'_> {
    /*     fn init(
            &mut self,
            _req: &fuser::Request,
            _kconfig: &mut fuser::KernelConfig,
        ) -> Result<(), c_int> {
            Ok(())
        }
    */
    fn destroy(&mut self) {}

    fn lookup(
        &mut self,
        _req: &fuser::Request,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        println!("lookup {} {:#?}", parent, name);
        let result = self
            .fs
            .backing
            .get(parent as usize)
            .unwrap()
            .children
            .as_ref()
            .unwrap()
            .get(name.to_str().unwrap());
        match result {
            Some(x) => reply.entry(&Duration::from_secs(300), &self.file_attr(*x), 0),
            None => reply.error(ENOENT),
        }
    }

    //    fn forget(&mut self, _req: &fuser::Request, _ino: u64, _nlookup: u64) {}

    fn getattr(
        &mut self,
        _req: &fuser::Request,
        _ino: u64,
        _fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        reply.attr(&Duration::from_secs(300), &self.file_attr(_ino as usize));
    }

    fn readlink(&mut self, _req: &fuser::Request, _ino: u64, reply: fuser::ReplyData) {
        println!("READLINK");
        reply.error(ENOSYS);
    }

    fn open(&mut self, _req: &fuser::Request, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        println!("open {}", ino);

        let id = &self.fs.backing[ino as usize].id;

        let mbfile = self.get_mbfile(id);

        let id = self.fs.backing[ino as usize].id.as_stringid();
        let id = id.as_str();
        let mut folder = self.basepath.join(&id[0..2]);
        folder.push(id);

        let encdata = mbfile.encryption_key.unwrap().0.data;

        let mut key = [0; 32];

        self.keys[&u32::from_le_bytes(encdata.as_ref()[0..4].try_into().unwrap())]
            .unwrap(&encdata.as_ref()[4..], &mut key)
            .unwrap();

        let mut cbc_cache = CbcCache::new(key, &[0; 16], 0);

        let size = dbg!(mbfile.size);
        println!("open {} {} {:?}", ino, size, &folder);

        let Ok(mut f) = std::fs::File::open(&folder) else {
            eprintln!("Can't open file: {}", folder.to_str().unwrap());
            return reply.error(EIO);
        };

        'verify_digest: {
            if self.options.verify_digests {
                break 'verify_digest;
            }
            let Some(digest) = mbfile.digest else {
                println!("No Digest Available");
                break 'verify_digest;
            };
            let mut hasher = sha1::Sha1::new();
            let Ok(_) = std::io::copy(&mut f, &mut hasher) else {
                eprintln!("Can't digest file: {}", folder.to_str().unwrap());
                return reply.error(EIO);
            };
            let hash = hasher.finalize();
            if hash.as_slice() != digest.as_ref() {
                eprintln!("Invalid digest file: {}", folder.to_str().unwrap());
                eprintln!(
                    "expected: {:?}, got: {:?}",
                    &hash.as_slice(),
                    digest.as_ref()
                );
                return reply.error(EIO);
            }
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0)).unwrap();
        }

        let filesize = dbg!(f.metadata().unwrap().len());
        assert!(filesize % 16 == 0);

        let size = if filesize < size {
            dbg!("!!!!MISMATCH!!!!");
            // TODO?: zero extend file in reader?
            filesize - 16
        } else {
            size
        };

        if !enc_reader::has_correct_pkcs5_padding(&f, &mut cbc_cache, filesize - 16) {
            return reply.error(EIO);
        }

        let handle = Box::into_raw(Box::new(OpenFile {
            encrypted_size: size,
            zero_size: mbfile.size,
            f,
            cbc_cache,
        }));

        reply.opened(handle as u64, 0);
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        println!("read {} {} {}", _ino, offset, size);

        let fh = unsafe { &mut *(fh as *mut OpenFile) };

        if offset as u64 == fh.zero_size {
            return reply.data(&[]);
        }

        if offset as u64 > fh.zero_size {
            return reply.error(ENOENT);
        }

        let mut decrypt_size = size as u64;
        if offset as u64 + size as u64 > fh.encrypted_size {
            decrypt_size = fh.encrypted_size.saturating_sub(offset as u64);
        }
        let mut zero_size = size as u64;
        if offset as u64 + size as u64 > fh.zero_size {
            zero_size = fh.zero_size - offset as u64;
        }

        let mut buffer = vec![0; zero_size as usize];

        if decrypt_size > 0 {
            enc_reader::read_encrypted(
                &fh.f,
                &mut fh.cbc_cache,
                buffer.as_mut_ptr(),
                decrypt_size,
                offset as u64,
            );
        }

        reply.data(&buffer)
    }

    fn release(
        &mut self,
        _req: &fuser::Request,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        println!("release {} {} {}", _ino, _fh, _flags);
        unsafe {
            let _ = Box::from_raw(_fh as *mut OpenFile);
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &fuser::Request, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        println!("opendir {} {}", ino, _flags);
        match self
            .fs
            .backing
            .get(ino as usize)
            .map(|x: &crate::manifestdb::Inode| x.ftype)
        {
            // FOPEN_CACHE_DIR | FOPEN_KEEP_CACHE
            Some(FileType::Folder) => {
                println!("opendir opened");
                reply.opened(0, 0)
            }
            Some(FileType::File) => {
                println!("opendir ENOTDIR");
                reply.error(ENOTDIR)
            }
            None => {
                println!("opendir ENOENT");
                reply.error(ENOENT)
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        println!("readdir {} {}", ino, offset);
        let inode = self.fs.backing.get(ino as usize).unwrap();
        for x in inode
            .children
            .as_ref()
            .unwrap()
            .iter()
            .enumerate()
            .skip(offset as usize)
        {
            println!("readdir {} {} {} {}", ino, x.0, x.1 .0, x.1 .1);
            if reply.add(
                *x.1 .1 as u64,
                x.0 as i64 + 1,
                self.fs.backing.get(*x.1 .1).unwrap().ftype.into(),
                x.1 .0,
            ) {
                break;
            }
        }

        reply.ok()
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        println!("releasedir");
        reply.ok();
    }

    fn statfs(&mut self, _req: &fuser::Request, _ino: u64, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn getxattr(
        &mut self,
        _req: &fuser::Request,
        ino: u64,
        name: &std::ffi::OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        println!("getxattr {} {}", ino, name.to_str().unwrap());
        let id = &self.fs.backing[ino as usize].id;

        let mbfile = self.get_mbfile(id);

        let Some(plist) = mbfile.extended_attributes else {
            return reply.size(0);
        };

        let Some(dict) = plist.0.as_dictionary() else {
            return reply.error(EIO);
        };

        let Some(value) = dict.get(name.to_str().unwrap()) else {
            return reply.error(ENODATA);
        };

        let Some(data) = value.as_data() else {
            return reply.error(EIO);
        };

        if size == 0 {
            return reply.size(data.len() as u32);
        }

        if data.len() > size as usize {
            return reply.error(ERANGE);
        };

        reply.data(data);
    }

    fn listxattr(&mut self, _req: &fuser::Request, ino: u64, size: u32, reply: fuser::ReplyXattr) {
        println!("listxattr {} {}", ino, size);

        if ino < 1 {
            return reply.size(0);
        }

        let id = &self.fs.backing[ino as usize].id;

        let mbfile = self.get_mbfile(id);

        let Some(plist) = mbfile.extended_attributes else {
            return reply.size(0);
        };

        let Some(dict) = plist.0.as_dictionary() else {
            return reply.error(EIO);
        };

        let reply_size = dict
            .keys()
            .fold(0u32, |acc, key| acc.saturating_add(key.len() as u32 + 1));

        if reply_size == u32::MAX {
            return reply.error(E2BIG);
        }

        if size == 0 {
            return reply.size(reply_size);
        }

        if reply_size > size {
            return reply.error(ERANGE);
        }

        let mut replydata = Vec::with_capacity(reply_size as usize);

        for key in dict.keys() {
            replydata.extend_from_slice(key.as_bytes());
            replydata.push(0);
        }

        reply.data(dbg!(&replydata));
    }

    fn access(&mut self, _req: &fuser::Request, _ino: u64, _mask: i32, reply: fuser::ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /*    fn create(
        &mut self,
        _req: &fuser::Request,
        _parent: u64,
        _name: &std::ffi::OsStr,
        _mode: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        reply.error(ENOSYS);
    }*/
}
