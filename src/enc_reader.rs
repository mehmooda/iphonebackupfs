use core::num;
use std::{fs::File, os::unix::fs::FileExt};

use aes::cipher::{BlockDecryptMut, KeyIvInit};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct CbcCache {
    cbc: Aes256CbcDec,
    key: [u8; 32],
    offset: u64,
}

impl CbcCache {
    pub fn new(key: [u8; 32], iv: &[u8; 16], offset: u64) -> Self {
        CbcCache {
            cbc: Aes256CbcDec::new_from_slices(&key, iv).unwrap(),
            key,
            offset,
        }
    }

    fn recreate(&mut self, iv: &[u8; 16], offset: u64) {
        self.cbc = Aes256CbcDec::new_from_slices(&self.key, iv).unwrap();
        self.offset = offset;
    }

    fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    fn get_offset(&self) -> u64 {
        self.offset
    }
}

pub fn has_correct_pkcs5_padding(
    file: &File,
    cbc_cache: &mut CbcCache,
    padding_offset: u64,
) -> bool {
    let mut bytes = [0u8; 16];

    read_encrypted(file, cbc_cache, bytes.as_mut_ptr(), 16, padding_offset);

    let num_padding_bytes = bytes[15];

    if num_padding_bytes > 0x10 {
        return false;
    }
    bytes[16 - num_padding_bytes as usize..]
        .iter()
        .all(|x| *x == num_padding_bytes)
}

pub fn read_encrypted(
    file: &File,
    cbc_cache: &mut CbcCache,
    p_out: *mut u8,
    len: u64,
    offset: u64,
) {
    let foffset = offset % 16;

    if foffset != 0 {
        let to_write = 16 - foffset;
        let mut out = [0u8; 16];
        read_encrypted(
            file,
            cbc_cache,
            &mut out as *mut _ as _,
            16,
            offset - foffset,
        );
        unsafe {
            std::ptr::copy(
                out[foffset as usize..].as_ptr(),
                p_out as *mut _,
                std::cmp::min(to_write as usize, len as usize),
            );
        }
        if (len as i64 - to_write as i64) > 0 {
            return read_encrypted(
                file,
                cbc_cache,
                unsafe { p_out.add(to_write as usize) },
                len - to_write,
                offset + to_write,
            );
        }
        return;
    }

    let rem_len = len % 16;
    let len = len - rem_len;

    assert!(offset % 16 == 0);

    let buf = unsafe { std::slice::from_raw_parts_mut(p_out as *mut u8, len as usize) };

    file.read_exact_at(buf, offset as u64).unwrap();

    if cbc_cache.get_offset() != offset {
        let mut iv = [0; 16];

        if offset != 0 {
            file.read_exact_at(&mut iv, offset as u64 - 16).unwrap();
        }
        cbc_cache.recreate(&iv, offset);
    }

    cbc_cache.cbc.decrypt_blocks_mut(unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as _, len as usize / 16)
    });

    cbc_cache.set_offset(offset + len);

    if rem_len > 0 {
        let mut out = [0u8; 16];
        read_encrypted(file, cbc_cache, &mut out as *mut _ as _, 16, offset + len);
        unsafe {
            std::ptr::copy(
                out.as_ptr(),
                p_out.add(len as usize) as *mut _,
                rem_len as usize,
            );
        }
    }
}
