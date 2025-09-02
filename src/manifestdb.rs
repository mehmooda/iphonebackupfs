#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NSKeyedArchiver {
    #[serde(rename = "$version")]
    version: u64,
    #[serde(rename = "$archiver")]
    archiver: String,
    #[serde(rename = "$top")]
    top: NSKeyedArchiverTop,
    #[serde(rename = "$objects")]
    objects: Vec<plist::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NSKeyedArchiverTop {
    root: plist::Uid,
}

#[derive(Debug, serde::Deserialize)]
struct NSKeyedArchiverClass {
    #[serde(rename = "$classname")]
    classname: String,
    #[serde(rename = "$classes")]
    classes: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct MBFile {
    pub last_modified: u64,
    pub flags: u64,
    #[serde(deserialize_with = "use_nska_objects", default)]
    pub extended_attributes: Option<NestedPlist>,
    pub group_i_d: i64,
    #[allow(dead_code)]
    #[serde(deserialize_with = "use_nska_objects", default)]
    pub target: Option<String>,
    pub last_status_change: u64,
    #[allow(dead_code)]
    #[serde(deserialize_with = "use_nska_objects")]
    pub relative_path: String,
    pub birth: u64,
    #[serde(deserialize_with = "use_nska_objects", default)]
    pub encryption_key: Option<NSKeyed<NSMutableData>>,
    pub size: u64,
    #[serde(deserialize_with = "use_nska_objects", default)]
    pub digest: Option<plist::Data>,
    #[allow(dead_code)]
    pub inode_number: u64,
    #[allow(dead_code)]
    pub mode: u64,
    pub user_i_d: i64,
    #[allow(dead_code)]
    pub protection_class: u64,
    #[serde(rename = "$class")]
    _skipped: serde::de::IgnoredAny,
}

impl rusqlite::types::FromSql for MBFile {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(
            plist::from_bytes::<NSKeyedArchive<NSKeyed<MBFile>>>(value.as_blob().unwrap())
                .unwrap()
                .0
                 .0,
        )
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct NSMutableData {
    #[serde(rename = "NS.data")]
    pub data: plist::Data,
    #[serde(rename = "$class")]
    _skipped: serde::de::IgnoredAny,
}

impl NSClassName for NSMutableData {
    fn verify(class: &plist::Value) -> Result<(), String> {
        let class: NSKeyedArchiverClass = plist::from_value(class)
            .map_err(|e| format!("Error parsing NSKeyedArchiveClassTree: {}", e))?;

        if class.classname != "NSMutableData"
            || class.classes != ["NSMutableData", "NSData", "NSObject"]
        {
            return Err(format!(
                "Expected NSMutableData class got {:#?}",
                class.classes
            ));
        }

        Ok(())
    }
}

fn use_nska_objects<'de, D, T: serde::de::DeserializeOwned>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let x = plist::Uid::deserialize(deserializer)?;
    thread_scoped_ref::with(&NSKA_OBJECTS, |objects| {
        Ok(plist::from_value(&objects.unwrap()[x.get() as usize])
            .map_err(|e| format!("Error parsing {}: {}", std::any::type_name::<T>(), e))
            .map_err(D::Error::custom)?)
    })
}

thread_scoped_ref::thread_scoped_ref!(NSKA_OBJECTS, [plist::Value]);

#[derive(Debug)]
pub struct NSKeyed<T: serde::de::DeserializeOwned>(pub T);

trait NSClassName {
    fn get_and_verify_class(value: &plist::Value) -> Result<(), String> {
        thread_scoped_ref::with(&NSKA_OBJECTS, |objects| {
            let class_ref = value
                .as_dictionary()
                .ok_or_else(|| "Expected NSKeyedObject to be Dictionary")?
                .get("$class")
                .ok_or_else(|| "Expected NSKeyedObject.$class to exist")?
                .as_uid()
                .ok_or_else(|| "Expected NSKeyedObject.$class to be an Uid")?
                .get();

            let class = objects
                .unwrap()
                .get(class_ref as usize)
                .ok_or_else(|| "Expected objects[objects[root].$class] to exist")?;

            Self::verify(class)
        })
    }

    fn verify(class: &plist::Value) -> Result<(), String>;
}

impl NSClassName for MBFile {
    fn verify(class: &plist::Value) -> Result<(), String> {
        let class: NSKeyedArchiverClass = plist::from_value(class)
            .map_err(|e| format!("Error parsing NSKeyedArchiveClassTree: {}", e))?;

        if class.classname != "MBFile" || class.classes != ["MBFile", "NSObject"] {
            return Err(format!("Expected MBFile class got {:#?}", class.classes));
        }

        Ok(())
    }
}

impl<'de, T: serde::de::DeserializeOwned + NSClassName> serde::Deserialize<'de> for NSKeyed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = plist::Value::deserialize(deserializer)?;

        T::get_and_verify_class(&value).map_err(D::Error::custom)?;

        Ok(NSKeyed(
            plist::from_value(&value)
                .map_err(|e| format!("Error parsing {}: {}", std::any::type_name::<T>(), e))
                .map_err(D::Error::custom)?,
        ))
    }
}

#[derive(Debug)]
pub struct NSKeyedArchive<T: serde::de::DeserializeOwned>(pub T);

impl<'de, T: serde::de::DeserializeOwned> serde::Deserialize<'de> for NSKeyedArchive<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let nska = NSKeyedArchiver::deserialize(deserializer)?;
        if nska.version != 100000 {
            return Err(D::Error::custom(format!(
                "Incorrect version: {}",
                nska.version
            )));
        }
        if nska.archiver != "NSKeyedArchiver" {
            return Err(D::Error::custom(format!(
                "Incorrect archiver: {}",
                nska.archiver
            )));
        }

        thread_scoped_ref::scoped(&NSKA_OBJECTS, &nska.objects, || {
            Ok(NSKeyedArchive(
                plist::from_value(
                    nska.objects
                        .get(nska.top.root.get() as usize)
                        .ok_or_else(|| "Expected objects[top.root] to exist")
                        .map_err(D::Error::custom)?,
                )
                .map_err(|e| format!("Error parsing {}: {}", std::any::type_name::<T>(), e))
                .map_err(D::Error::custom)?,
            ))
        })
    }
}

#[derive(Debug)]
pub struct NestedPlist(pub plist::Value);

use serde::{de::Error, Deserialize};

impl<'de> serde::Deserialize<'de> for NestedPlist {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let x = plist::Data::deserialize(deserializer)?;
        let y = plist::from_bytes(x.as_ref()).map_err(|z| D::Error::custom(z))?;
        Ok(NestedPlist(y))
    }
}

/*
Easily navigable format

: 20
FLAGS: 4
PARENT_PTR: 4
SIZE: 4
NAME_PTR: 4
*/
//

#[derive(Debug)]
pub struct FS {
    pub backing: Vec<Inode>,
}

impl FS {
    pub fn new() -> Self {
        Self {
            backing: vec![
                Inode {
                    id: RawId([0; 20]),
                    ftype: FileType::File,
                    children: None,
                }, // inode 0 doesn't exist
                Inode {
                    id: RawId([0; 20]),
                    ftype: FileType::Folder,
                    children: Some(Default::default()),
                },
            ], // root inode
        }
    }
}

#[derive(Debug)]
pub struct Inode {
    pub id: RawId,
    pub ftype: FileType,
    pub children: Option<std::collections::BTreeMap<String, usize>>,
}

#[derive(Debug)]
pub struct RawId([u8; 20]);
#[derive(Debug)]
pub struct StringId([u8; 40]);

impl RawId {
    pub fn as_stringid(&self) -> StringId {
        use std::io::Write;
        struct ToHex<'a>(&'a [u8]);

        impl<'a> std::fmt::LowerHex for ToHex<'a> {
            fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
                for byte in self.0 {
                    fmtr.write_fmt(format_args!("{:02x}", byte))?;
                }
                Ok(())
            }
        }
        let mut id_str = [0u8; 40];
        write!(&mut id_str[..], "{:x}", ToHex(&self.0[..])).unwrap();

        StringId(id_str)
    }
}

impl StringId {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0[..]).unwrap()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum FileType {
    File,
    Folder,
}

impl std::convert::Into<fuser::FileType> for FileType {
    fn into(self) -> fuser::FileType {
        match self {
            FileType::File => fuser::FileType::RegularFile,
            FileType::Folder => fuser::FileType::Directory,
        }
    }
}

impl std::convert::From<i64> for FileType {
    fn from(value: i64) -> Self {
        match value {
            1 => FileType::File,
            2 => FileType::Folder,
            _ => panic!("Invalid flags"),
        }
    }
}

impl FS {
    fn retain_func(&mut self, v: &usize) -> bool {
        let node = &mut self.backing[*v];
        match node.ftype {
            FileType::File => return true,
            FileType::Folder => (),
        };

        let mut children = node.children.take();

        children
            .as_mut()
            .unwrap()
            .retain(|_, v| Self::retain_func(self, v));

        self.backing[*v].children.replace(children.unwrap());

        if self.backing[*v].children.as_ref().unwrap().is_empty() {
            return false;
        }
        true
    }

    pub fn remove_empty_directories(&mut self) {
        let mut children = self.backing[1].children.take();

        children
            .as_mut()
            .unwrap()
            .retain(|_, v| Self::retain_func(self, v));

        self.backing[1].children.replace(children.unwrap());
    }

    // Parent folder must be inserted before children
    pub fn insert_file(&mut self, domain: &str, path: &str, id: &str, ftype: FileType) {
        let mut id_b = [0u8; 20];

        let mut id_i = id
            .as_bytes()
            .chunks(2)
            .map(std::str::from_utf8)
            .map(Result::unwrap)
            .map(|s| u8::from_str_radix(s, 16))
            .map(Result::unwrap);

        id_b.fill_with(|| id_i.next().unwrap());

        let new_inode = self.backing.len();
        if path == "" {
            assert!(self.backing[1]
                .children
                .as_mut()
                .unwrap()
                .insert(domain.to_string(), new_inode)
                .is_none());
            self.backing.push(Inode {
                id: RawId(id_b),
                ftype: ftype,
                children: match ftype {
                    FileType::Folder => Some(std::collections::BTreeMap::new()),
                    FileType::File => None,
                },
            });

            return;
        }

        let mut inode_nr = self.backing[1].children.as_ref().unwrap()[domain];

        let path = std::path::Path::new(path);

        for x in path.parent().unwrap().components() {
            inode_nr =
                self.backing[inode_nr].children.as_ref().unwrap()[x.as_os_str().to_str().unwrap()]
        }

        assert!(self.backing[inode_nr]
            .children
            .as_mut()
            .unwrap()
            .insert(
                path.components()
                    .last()
                    .unwrap()
                    .as_os_str()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                new_inode
            )
            .is_none());
        self.backing.push(Inode {
            id: RawId(id_b),
            ftype: ftype,
            children: match ftype {
                FileType::Folder => Some(std::collections::BTreeMap::new()),
                FileType::File => None,
            },
        });
    }
}
