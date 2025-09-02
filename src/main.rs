fn main() {
    let base_path = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let mountpoint = std::path::PathBuf::from(std::env::args().nth(2).unwrap());
    let password = std::env::args().nth(3).unwrap();

    println!("** READING Manifest.plist");

    let manifest: manifest::Manifest = manifest::read_manifest(&base_path);

    println!("** VERIFYING PASSPHRASE");

    let keys = verify_passphrase(manifest.backup_key_bag, password.as_bytes());

    let mut manifestdb_key = [0u8; 32];
    keys[&u32::from_le_bytes(manifest.manifest_key.as_ref()[0..4].try_into().unwrap())]
        .unwrap(&manifest.manifest_key.as_ref()[4..], &mut manifestdb_key)
        .unwrap();

    vfs::register(manifestdb_key);

    println!("** READING Manifest.db");

    let mut fs = manifestdb::FS::new();

    let con = rusqlite::Connection::open(base_path.join("Manifest.db")).unwrap();
    let mut sta = con
        .prepare("SELECT * FROM Files ORDER BY domain, relativePath")
        .unwrap();
    let mut rows = sta.query(()).unwrap();

    while let Some(row) = rows.next().unwrap() {
        let domain = row.get_ref(1).unwrap().as_str().unwrap();
        let path = row.get_ref(2).unwrap().as_str().unwrap();
        let id = row.get_ref(0).unwrap().as_str().unwrap();
        let ftype = row.get_ref(3).unwrap().as_i64().unwrap();
        let data = row.get_ref(4).unwrap().as_blob().unwrap();

        let _x = plist::from_bytes::<
            manifestdb::NSKeyedArchive<manifestdb::NSKeyed<manifestdb::MBFile>>,
        >(data)
        .map_err(|e| {
            dbg!(plist::from_bytes::<plist::Value>(data)).unwrap();
            e
        })
        .unwrap();

        if ftype != 4 {
            fs.insert_file(domain, path, id, ftype.into());
        }
    }

    println!("** Removing Empty Directories");

    fs.remove_empty_directories();

    let filesystem = backupfuse::BackupFS::new(fs, &con, keys, base_path);

    println!("** Serving Filesystem");

    fuser::mount2(filesystem, mountpoint, &[fuser::MountOption::AllowOther]).unwrap()
}

mod manifestdb;

mod backupfuse;

fn verify_passphrase(
    bkb: manifest::KeyBag,
    password: &[u8],
) -> std::collections::BTreeMap<u32, aes_kw::KekAes256> {
    let mut res = std::collections::BTreeMap::new();

    let mut round1 = [0u8; 32];
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &bkb.dpsl, bkb.dpic, &mut round1);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&round1, &bkb.salt, bkb.iter, &mut key);

    let kek = aes_kw::Kek::from(key);
    for x in &bkb.others {
        if x.wrap & 0x2 == 0x2 {
            let mut ukey = [0u8; 32];
            if let Err(x) = kek.unwrap(&x.wpky, &mut ukey) {
                if let aes_kw::Error::IntegrityCheckFailed = x {
                    panic!("Incorrect Passphrase")
                }
                panic!("Unknown AES_KW ERROR {}", x);
            }
            res.insert(x.clas, aes_kw::Kek::from(ukey));
        }
    }
    res
}
mod enc_reader;
mod manifest;
mod vfs;
