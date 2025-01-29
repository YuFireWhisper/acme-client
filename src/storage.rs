use std::{
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Key is invalid: {0}")]
    InvalidKey(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Key is a dir: {0}")]
    IsDir(String),
    #[error("Not a directory: {0}")]
    NotDirectory(String),
    #[error("Lock poisoned")]
    LockPoisoned,
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub trait Storage: Send + Sync {
    fn create_dir_all(&self, key: &str) -> Result<()>;
    fn read_file(&self, key: &str) -> Result<Vec<u8>>;
    fn write_file(&self, key: &str, value: &[u8]) -> Result<()>;
    fn remove(&self, key: &str) -> Result<()>;
    fn exists(&self, key: &str) -> Result<bool>;
    fn is_dir(&self, key: &str) -> Result<bool>;
}

struct KeyUtils;

impl KeyUtils {
    fn normalize(key: &str) -> Result<PathBuf> {
        if key.is_empty() {
            return Err(StorageError::InvalidKey("Empty key".to_string()));
        }

        if key.contains('\0') || key.contains('\n') || key.contains('\r') {
            return Err(StorageError::InvalidKey(format!(
                "Invalid characters in key: {}",
                key
            )));
        }

        if key.contains("//") {
            return Err(StorageError::InvalidKey(format!(
                "Double slashes not allowed in key: {}",
                key
            )));
        }

        let path = Path::new(key);
        let mut normalized = PathBuf::from("/");

        for component in path.components() {
            match component {
                std::path::Component::RootDir => normalized = PathBuf::from("/"),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if normalized.as_os_str() == "/" {
                        return Err(StorageError::InvalidKey(format!(
                            "Cannot use '..' to escape root directory: {}",
                            key
                        )));
                    }
                    normalized.pop();
                }
                std::path::Component::Normal(name) => {
                    if let Some(name_str) = name.to_str() {
                        if name_str.contains('/') || name_str.contains('\\') {
                            return Err(StorageError::InvalidKey(format!(
                                "Invalid path component: {}",
                                name_str
                            )));
                        }
                        normalized.push(name_str);
                    } else {
                        return Err(StorageError::InvalidKey(format!(
                            "Non-UTF8 path component in: {}",
                            key
                        )));
                    }
                }
                _ => return Err(StorageError::InvalidKey(format!("Invalid path: {}", key))),
            }
        }

        Ok(normalized)
    }

    fn parent(path: &Path) -> Option<PathBuf> {
        path.parent().map(|p| p.to_path_buf())
    }

    fn verify_directory_key(key: &str) -> Result<PathBuf> {
        let path = Self::normalize(key)?;
        if path.to_string_lossy().ends_with('/') {
            Ok(path)
        } else {
            let mut path = path;
            path.push("");
            Ok(path)
        }
    }

    fn verify_file_key(key: &str) -> Result<PathBuf> {
        let path = Self::normalize(key)?;

        if key.ends_with('/') || path.to_string_lossy().ends_with('/') {
            return Err(StorageError::InvalidKey(format!(
                "File key cannot end with '/': {}",
                key
            )));
        }

        Ok(path)
    }
}

pub struct FileStorage {
    index: Arc<RwLock<StorageIndex>>,
    file: Arc<RwLock<std::fs::File>>,
}

struct StorageIndex {
    entries: HashMap<PathBuf, EntryMetadata>,
}

#[derive(Clone, Copy)]
struct EntryMetadata {
    offset: u64,
    is_dir: bool,
    is_deleted: bool,
}

impl FileStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        let index = Self::build_index(&file)?;

        Ok(Self {
            index: Arc::new(RwLock::new(index)),
            file: Arc::new(RwLock::new(file)),
        })
    }

    fn build_index(file: &std::fs::File) -> Result<StorageIndex> {
        let mut reader = io::BufReader::new(file);
        let mut entries = HashMap::new();
        let mut offset = 0;

        loop {
            let mut header = [0u8; 8];
            match reader.read_exact(&mut header) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            let (key_len, flags) = Self::parse_header(&header);
            let mut key_buf = vec![0u8; key_len as usize];
            reader.read_exact(&mut key_buf)?;

            let key = String::from_utf8_lossy(&key_buf);
            let path = KeyUtils::normalize(&key)?;

            let mut size_buf = [0u8; 4];
            reader.read_exact(&mut size_buf)?;
            let size = u32::from_le_bytes(size_buf);

            entries.insert(
                path,
                EntryMetadata {
                    offset,
                    is_dir: flags & 1 == 1,
                    is_deleted: flags & 2 == 2,
                },
            );

            reader.seek(SeekFrom::Current(size as i64))?;
            offset += 8 + key_len as u64 + 4 + size as u64;
        }

        Ok(StorageIndex { entries })
    }

    fn parse_header(header: &[u8; 8]) -> (u32, u8) {
        let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let flags = header[4];
        (key_len, flags)
    }

    fn write_entry(&self, key: &Path, value: &[u8], is_dir: bool) -> Result<()> {
        let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
        let key_str = key.to_string_lossy();
        let key_bytes = key_str.as_bytes();

        let header = Self::create_header(key_bytes.len() as u32, is_dir, false);
        file.write_all(&header)?;

        file.write_all(key_bytes)?;
        let size = value.len() as u32;
        file.write_all(&size.to_le_bytes())?;
        file.write_all(value)?;

        let offset = file.stream_position()? - size as u64 - key_bytes.len() as u64 - 12;
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
        index.entries.insert(
            key.to_path_buf(),
            EntryMetadata {
                offset,
                is_dir,
                is_deleted: false,
            },
        );

        Ok(())
    }

    fn create_header(key_len: u32, is_dir: bool, is_deleted: bool) -> [u8; 8] {
        let mut header = [0u8; 8];
        header[0..4].copy_from_slice(&key_len.to_le_bytes());
        header[4] = if is_dir { 1 } else { 0 } | if is_deleted { 2 } else { 0 };
        header
    }
}

impl Storage for FileStorage {
    fn create_dir_all(&self, key: &str) -> Result<()> {
        let path = KeyUtils::verify_directory_key(key)?;

        let mut current = PathBuf::from("/");
        for component in path.components().skip(1) {
            current.push(component);
            if !self.exists(&current.to_string_lossy())? {
                self.write_entry(&current, &[], true)?;
            }
        }

        Ok(())
    }

    fn read_file(&self, key: &str) -> Result<Vec<u8>> {
        let path = KeyUtils::verify_file_key(key)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;

        if let Some(metadata) = index.entries.get(&path) {
            if metadata.is_deleted {
                return Err(StorageError::NotFound(key.to_string()));
            }

            if metadata.is_dir {
                return Err(StorageError::IsDir(key.to_string()));
            }

            let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
            file.seek(SeekFrom::Start(metadata.offset))?;

            let mut header = [0u8; 8];
            file.read_exact(&mut header)?;
            let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap());
            file.seek(SeekFrom::Current(key_len as i64))?;

            let mut size_buf = [0u8; 4];
            file.read_exact(&mut size_buf)?;
            let size = u32::from_le_bytes(size_buf);

            let mut data = vec![0u8; size as usize];
            file.read_exact(&mut data)?;

            Ok(data)
        } else {
            Err(StorageError::NotFound(key.to_string()))
        }
    }

    fn write_file(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = KeyUtils::verify_file_key(key)?;

        if let Some(parent) = KeyUtils::parent(&path) {
            if !self.exists(&parent.to_string_lossy())? {
                return Err(StorageError::NotFound(
                    parent.to_string_lossy().into_owned(),
                ));
            }
            if !self.is_dir(&parent.to_string_lossy())? {
                return Err(StorageError::NotDirectory(
                    parent.to_string_lossy().into_owned(),
                ));
            }
        }

        self.write_entry(&path, value, false)
    }

    fn remove(&self, key: &str) -> Result<()> {
        let path = KeyUtils::normalize(key)?;
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;

        if let Some(metadata) = index.entries.get_mut(&path) {
            metadata.is_deleted = true;

            let mut file = self.file.write().map_err(|_| StorageError::LockPoisoned)?;
            file.seek(SeekFrom::Start(metadata.offset + 4))?;
            file.write_all(&[if metadata.is_dir { 3 } else { 2 }])?;
        }

        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
        Ok(index.entries.get(&path).is_some_and(|m| !m.is_deleted))
    }

    fn is_dir(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        let index = self.index.read().map_err(|_| StorageError::LockPoisoned)?;
        Ok(index
            .entries
            .get(&path)
            .is_some_and(|m| m.is_dir && !m.is_deleted))
    }
}

pub struct MemStorage {
    data: Arc<RwLock<HashMap<PathBuf, Vec<u8>>>>,
    dirs: Arc<RwLock<HashMap<PathBuf, ()>>>,
}

impl Default for MemStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStorage {
    pub fn new() -> Self {
        let mut dirs = HashMap::new();
        dirs.insert(PathBuf::from("/"), ());

        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            dirs: Arc::new(RwLock::new(dirs)),
        }
    }
}

impl Storage for MemStorage {
    fn create_dir_all(&self, key: &str) -> Result<()> {
        let path = KeyUtils::verify_directory_key(key)?;
        let mut current = PathBuf::from("/");

        let mut dirs = self.dirs.write().map_err(|_| StorageError::LockPoisoned)?;
        for component in path.components().skip(1) {
            current.push(component);
            dirs.entry(current.clone()).or_insert(());
        }

        Ok(())
    }

    fn read_file(&self, key: &str) -> Result<Vec<u8>> {
        let path = KeyUtils::verify_file_key(key)?;
        let data = self.data.read().map_err(|_| StorageError::LockPoisoned)?;
        if let Some(value) = data.get(&path) {
            Ok(value.clone())
        } else {
            Err(StorageError::NotFound(key.to_string()))
        }
    }

    fn write_file(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = KeyUtils::verify_file_key(key)?;

        if let Some(parent) = KeyUtils::parent(&path) {
            if !self.exists(&parent.to_string_lossy())? {
                return Err(StorageError::NotFound(
                    parent.to_string_lossy().into_owned(),
                ));
            }
            if !self.is_dir(&parent.to_string_lossy())? {
                return Err(StorageError::NotDirectory(
                    parent.to_string_lossy().into_owned(),
                ));
            }
        }

        self.data
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .insert(path, value.to_vec());

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        let path = KeyUtils::normalize(key)?;
        self.data
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .remove(&path);
        self.dirs
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .remove(&path);
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        Ok(self
            .data
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .contains_key(&path)
            || self
                .dirs
                .read()
                .map_err(|_| StorageError::LockPoisoned)?
                .contains_key(&path))
    }

    fn is_dir(&self, key: &str) -> Result<bool> {
        let path = KeyUtils::normalize(key)?;
        Ok(self
            .dirs
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .contains_key(&path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_storages() -> Vec<Box<dyn Storage>> {
        vec![
            Box::new(MemStorage::new()),
            Box::new(FileStorage::open(NamedTempFile::new().unwrap().path()).unwrap()),
        ]
    }

    #[test]
    fn test_value_with_special_chars() {
        for storage in create_storages() {
            let test_data = vec![
                ("normal.txt", b"http://example.com" as &[u8]),
                ("slashes.txt", b"path/with/slashes"),
                ("url.txt", b"https://user:pass@example.com/path?query=1"),
                ("control.txt", b"Contains\r\nNewlines\tand\x00NullBytes"),
                ("unicode.txt", "包含Unicode字符".as_bytes()),
            ];

            storage.create_dir_all("/test").unwrap();

            for (key, value) in &test_data {
                let full_key = format!("/test/{}", key);
                storage.write_file(&full_key, value).unwrap();
            }

            for (key, expected_value) in &test_data {
                let full_key = format!("/test/{}", key);
                let read_value = storage.read_file(&full_key).unwrap();
                assert_eq!(&read_value, expected_value);
            }
        }
    }

    #[test]
    fn test_invalid_keys() {
        for storage in create_storages() {
            let invalid_keys = vec![
                "//double/slash",
                "/path/with/trailing//",
                "/bad\0null",
                "/bad\nchar",
                "../outside",
            ];

            for key in invalid_keys {
                assert!(matches!(
                    storage.write_file(key, b"test"),
                    Err(StorageError::InvalidKey(_))
                ));
            }
        }
    }

    #[test]
    fn test_directory_validation() {
        for storage in create_storages() {
            assert!(storage.create_dir_all("/valid/dir/path/").is_ok());
            assert!(storage.create_dir_all("/another/valid/dir").is_ok());

            assert!(matches!(
                storage.write_file("/dir/with/trailing/", b"test"),
                Err(StorageError::InvalidKey(_))
            ));

            assert!(storage.is_dir("/valid/dir/path").unwrap());
            assert!(!storage.is_dir("/valid/dir/path/nonexistent").unwrap());
        }
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        for storage in create_storages() {
            let storage = Arc::new(storage);
            storage.create_dir_all("/concurrent").unwrap();

            let mut handles = vec![];

            for i in 0..10 {
                let storage = Arc::clone(&storage);
                let handle = thread::spawn(move || {
                    let key = format!("/concurrent/file{}.txt", i);
                    let value = format!("http://example.com/path{}/data", i);
                    storage.write_file(&key, value.as_bytes()).unwrap();
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            for i in 0..10 {
                let key = format!("/concurrent/file{}.txt", i);
                let expected = format!("http://example.com/path{}/data", i);
                let read_value = storage.read_file(&key).unwrap();
                assert_eq!(String::from_utf8_lossy(&read_value), expected);
            }
        }
    }
}
