use serde::Deserialize;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub(crate) struct Manifest {
    #[serde(deserialize_with = "read_backup_key_bag")]
    pub backup_key_bag: KeyBag,
    pub version: String,
    pub date: chrono::DateTime<chrono::Utc>,
    pub system_domains_version: String,
    pub manifest_key: plist::Data,
    pub was_passcode_set: bool,
    pub lockdown: plist::Value,
    pub applications: plist::Value,
    pub is_encrypted: bool,
}

#[derive(Debug)]
pub struct KeyBag {
    pub vers: u32,
    pub ktype: u32,
    pub uuid: [u8; 16],
    pub hmck: Vec<u8>,
    pub wrap: u32,
    pub salt: Vec<u8>,
    pub iter: u32,
    pub dpwt: u32,
    pub dpic: u32,
    pub dpsl: Vec<u8>,
    pub others: Vec<KeyBagClass>,
}

#[derive(Debug)]
pub struct KeyBagClass {
    pub uuid: [u8; 16],
    pub clas: u32,
    pub wrap: u32,
    pub ktyp: u32,
    pub wpky: Vec<u8>,
}

pub(crate) fn read_manifest(path: &std::path::Path) -> Manifest {
    plist::from_file(path.join("Manifest.plist")).unwrap()
}

fn read_backup_key_bag<'de, D>(de: D) -> Result<KeyBag, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let data = plist::Data::deserialize(de)?;
    let mut input = data.as_ref();

    let vers;
    let ktype;
    let uuid;
    let hmck: Vec<u8>;
    let wrap;
    let salt;
    let iter;
    let dpwt;
    let dpic;
    let dpsl;
    let n = read_4tlv(input).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "VERS" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing VERS",
        ));
    }
    vers = u32::from_be_bytes(n.1 .1.try_into().unwrap());
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "TYPE" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing TYPE",
        ));
    }
    ktype = u32::from_be_bytes(n.1 .1.try_into().unwrap());
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "UUID" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing UUID",
        ));
    }
    uuid = n.1 .1.try_into().unwrap();
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "HMCK" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing HMCK",
        ));
    }
    hmck = n.1 .1.try_into().unwrap();
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "WRAP" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing WRAP",
        ));
    }
    wrap = u32::from_be_bytes(n.1 .1.try_into().unwrap());
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "SALT" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing SALT",
        ));
    }
    salt = n.1 .1.try_into().unwrap();
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "ITER" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing ITER",
        ));
    }
    iter = u32::from_be_bytes(n.1 .1.try_into().unwrap());
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "DPWT" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing DPWT",
        ));
    }
    dpwt = u32::from_be_bytes(n.1 .1.try_into().unwrap());
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "DPIC" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing DPIC",
        ));
    }
    dpic = u32::from_be_bytes(n.1 .1.try_into().unwrap());
    let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
    if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "DPSL" {
        return Err(<D::Error as serde::de::Error>::custom(
            "Unable to deserialize keybag: missing DPSL",
        ));
    }
    dpsl = n.1 .1.try_into().unwrap();
    input = n.0;
    let mut others = Vec::new();
    loop {
        let uuid;
        let clas;
        let wrap;
        let ktyp;
        let wpky;
        let n = read_4tlv(input).map_err(serde::de::Error::custom)?;
        if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "UUID" {
            return Err(<D::Error as serde::de::Error>::custom(
                "Unable to deserialize keybag: missing UUID",
            ));
        }
        uuid = n.1 .1.try_into().unwrap();
        let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
        if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "CLAS" {
            return Err(<D::Error as serde::de::Error>::custom(
                "Unable to deserialize keybag: missing CLAS",
            ));
        }
        clas = u32::from_be_bytes(n.1 .1.try_into().unwrap());
        let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
        if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "WRAP" {
            return Err(<D::Error as serde::de::Error>::custom(
                "Unable to deserialize keybag: missing WRAP",
            ));
        }
        wrap = u32::from_be_bytes(n.1 .1.try_into().unwrap());
        let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
        if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "KTYP" {
            return Err(<D::Error as serde::de::Error>::custom(
                "Unable to deserialize keybag: missing KTYP",
            ));
        }
        ktyp = u32::from_be_bytes(n.1 .1.try_into().unwrap());
        let n = read_4tlv(n.0).map_err(serde::de::Error::custom)?;
        if std::str::from_utf8(&n.1 .0.to_be_bytes()[..]).unwrap() != "WPKY" {
            return Err(<D::Error as serde::de::Error>::custom(
                "Unable to deserialize keybag: missing WPKY",
            ));
        }
        wpky = n.1 .1.try_into().unwrap();

        others.push(KeyBagClass {
            uuid,
            clas,
            wrap,
            ktyp,
            wpky,
        });

        input = n.0;
        if input.len() == 0 {
            break;
        }
    }
    let output = KeyBag {
        vers,
        ktype,
        uuid,
        hmck,
        wrap,
        salt,
        iter,
        dpwt,
        dpic,
        dpsl,
        others,
    };
    Ok(output)
}

fn read_4tlv(input: &[u8]) -> nom::IResult<&[u8], (u32, &[u8])> {
    let out =
        nom::sequence::pair(nom::number::complete::be_u32, nom::number::complete::be_u32)(input)?;
    let out2 = nom::bytes::complete::take(out.1 .1)(out.0)?;

    Ok((out2.0, (out.1 .0, out2.1)))
}
