use std::ffi::{c_void, CStr};

use libsqlite3_sys::{sqlite3_file, sqlite3_io_methods, sqlite3_vfs, SQLITE_NOTFOUND, SQLITE_OK};

use crate::enc_reader::{self, CbcCache};

static METHODS: sqlite3_io_methods = sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: None,
    xTruncate: None,
    xSync: None,
    xFileSize: Some(file_size),
    xLock: None,
    xUnlock: None,
    xCheckReservedLock: None,
    xFileControl: Some(file_control),
    xSectorSize: None,
    xDeviceCharacteristics: Some(device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

unsafe extern "C" fn read(
    mfile: *mut sqlite3_file,
    p_out: *mut c_void,
    len: i32,
    offset: i64,
) -> i32 {
    let sqlfile = &mut *(mfile as *mut VfsFile);

    enc_reader::read_encrypted(
        &sqlfile.stdfile,
        &mut sqlfile.cbc_cache,
        p_out as *mut _,
        len as u64,
        offset as u64,
    );

    SQLITE_OK
}

unsafe extern "C" fn file_size(file: *mut sqlite3_file, p_out: *mut i64) -> i32 {
    let file = &mut *(file as *mut VfsFile);
    *p_out = file.stdfile.metadata().unwrap().len() as i64;
    SQLITE_OK
}

unsafe extern "C" fn file_control(_file: *mut sqlite3_file, op: i32, _p_out: *mut c_void) -> i32 {
    dbg!(op);
    SQLITE_NOTFOUND
}

unsafe extern "C" fn device_characteristics(_file: *mut sqlite3_file) -> i32 {
    libsqlite3_sys::SQLITE_IOCAP_IMMUTABLE
}

unsafe extern "C" fn open(
    vfs: *mut sqlite3_vfs,
    zname: *const i8,
    file: *mut sqlite3_file,
    flags: i32,
    p_out_flags: *mut i32,
) -> i32 {
    // TEMP JOURNAL?
    if zname.is_null() {
        let vfs = libsqlite3_sys::sqlite3_vfs_find(b"unix-none\0" as *const _ as _);
        return (&*vfs).xOpen.unwrap()(vfs, zname, file, flags, p_out_flags);
    }

    let file = &mut *(file as *mut VfsFile);
    file.sqlfile.pMethods = &METHODS as *const _;
    std::ptr::write(
        &mut file.stdfile,
        std::fs::File::open(CStr::from_ptr(zname).to_str().unwrap()).unwrap(),
    );
    file.cbc_cache = CbcCache::new(*((*vfs).pAppData as *mut [u8; 32]), &[0; 16], 0);
    *p_out_flags = libsqlite3_sys::SQLITE_OPEN_READONLY;
    //    dbg!(flags);
    SQLITE_OK
}

unsafe extern "C" fn close(file: *mut sqlite3_file) -> i32 {
    let file = &mut *(file as *mut VfsFile);
    std::ptr::drop_in_place(&mut file.sqlfile);
    SQLITE_OK
}

#[repr(C)]
struct VfsFile {
    sqlfile: sqlite3_file,
    stdfile: std::fs::File,
    cbc_cache: CbcCache,
}

pub(crate) fn register(db_key: [u8; 32]) {
    let dvfs = unsafe { &*libsqlite3_sys::sqlite3_vfs_find(std::ptr::null()) };

    let vfs = Box::leak(Box::new(sqlite3_vfs {
        iVersion: 3,
        szOsFile: std::cmp::max(std::mem::size_of::<VfsFile>() as i32, dvfs.szOsFile),
        mxPathname: dvfs.mxPathname,
        pNext: std::ptr::null_mut(),
        zName: b"iosencryptedvfs\0" as *const _ as _,
        pAppData: Box::leak(Box::new(db_key)) as *mut _ as _,
        xOpen: Some(open),
        xDelete: None,
        xAccess: None,
        xFullPathname: dvfs.xFullPathname,
        xDlOpen: dvfs.xDlOpen,
        xDlError: dvfs.xDlError,
        xDlSym: dvfs.xDlSym,
        xDlClose: dvfs.xDlClose,
        xRandomness: dvfs.xRandomness,
        xSleep: dvfs.xSleep,
        xCurrentTime: dvfs.xCurrentTime,
        xGetLastError: dvfs.xGetLastError,
        xCurrentTimeInt64: dvfs.xCurrentTimeInt64,
        xSetSystemCall: dvfs.xSetSystemCall,
        xGetSystemCall: dvfs.xGetSystemCall,
        xNextSystemCall: dvfs.xNextSystemCall,
    }));

    unsafe {
        libsqlite3_sys::sqlite3_vfs_register(vfs, 1);
    }
}
