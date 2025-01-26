use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Arc, RwLock},
};

const KEY_SIZE: usize = 32;
const SEPARATOR: u8 = b'/';
const DIRECTORY_FLAG: u8 = 0xD0;
const DATA_FLAG: u8 = 0xDA;

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    KeyTooLong,
    InvalidPath,
    NotFound,
    NotDirectory,
    AlreadyExists,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::KeyTooLong => write!(f, "Key exceeds {} bytes", KEY_SIZE),
            Self::InvalidPath => write!(f, "Invalid path format"),
            Self::NotFound => write!(f, "Path not found"),
            Self::NotDirectory => write!(f, "Not a directory"),
            Self::AlreadyExists => write!(f, "Path already exists"),
        }
    }
}

impl Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

type Result<T> = std::result::Result<T, StorageError>;

#[derive(Clone)]
pub struct Storage {
    file: Arc<RwLock<File>>,
    path: Vec<u8>,
}

impl Storage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        Ok(Self {
            file: Arc::new(RwLock::new(file)),
            path: Vec::new(),
        })
    }

    pub fn create_dir_all(&self, path: &str) -> Result<Self> {
        let components = self.parse_path(path)?;
        let mut current = self.clone();

        for component in components {
            current = current.create_component(component)?;
        }
        Ok(current)
    }

    pub fn open_dir(&self, path: &str) -> Result<Option<Self>> {
        let target = self.resolve_path(path)?;
        self.get_metadata(&target)
            .map(|m| m.map(|_| self.with_path(target)))
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        let parent = self.parent_path(&full_path)?;

        if !self.is_directory(&parent)? {
            return Err(StorageError::NotFound);
        }

        let mut file = self.file.write()?;
        self.write_entry(&mut file, &full_path, DATA_FLAG, data)
    }

    pub fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let full_path = self.resolve_path(path)?;
        self.read_entry(&full_path, DATA_FLAG)
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        let mut file = self.file.write()?;
        self.write_entry(&mut file, &full_path, 0xDD, &[])
    }

    fn create_component(&self, name: &[u8]) -> Result<Self> {
        let mut new_path = self.path.clone();
        new_path.extend_from_slice(name);
        new_path.push(SEPARATOR);

        self.validate_key_length(&new_path)?;

        let mut file = self.file.write()?;
        if self.key_exists(&new_path)? {
            return Err(StorageError::AlreadyExists);
        }

        self.write_entry(&mut file, &new_path, DIRECTORY_FLAG, &[])?;
        Ok(self.with_path(new_path))
    }

    fn write_entry(
        &self,
        file: &mut File,
        key: &[u8],
        flag: u8,
        data: &[u8],
    ) -> Result<()> {
        let mut buffer = Vec::with_capacity(KEY_SIZE + 5 + data.len());
        buffer.extend_from_slice(&Self::fixed_key(key));
        buffer.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buffer.push(flag);
        buffer.extend_from_slice(data);

        file.seek(SeekFrom::End(0))?;
        file.write_all(&buffer)?;
        file.flush()?;
        Ok(())
    }

    fn read_entry(&self, key: &[u8], expected_flag: u8) -> Result<Option<Vec<u8>>> {
        let fixed_key = Self::fixed_key(key);
        let mut file = self.file.read()?;
        file.seek(SeekFrom::Start(0))?;

        let mut latest = None;
        loop {
            let mut current_key = [0u8; KEY_SIZE];
            if let Err(e) = file.read_exact(&mut current_key) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(e.into());
            }

            let mut len_buf = [0u8; 4];
            file.read_exact(&mut len_buf)?;
            let data_len = u32::from_le_bytes(len_buf);

            let mut flag = [0u8; 1];
            file.read_exact(&mut flag)?;

            let mut data = vec![0u8; data_len as usize];
            file.read_exact(&mut data)?;

            if current_key == fixed_key && flag[0] == expected_flag {
                latest = Some(data);
            }
        }

        Ok(latest)
    }

    fn get_metadata(&self, key: &[u8]) -> Result<Option<u8>> {
        let fixed_key = Self::fixed_key(key);
        let mut file = self.file.read()?;
        file.seek(SeekFrom::Start(0))?;

        loop {
            let mut current_key = [0u8; KEY_SIZE];
            if let Err(e) = file.read_exact(&mut current_key) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(e.into());
            }

            let mut len_buf = [0u8; 4];
            file.read_exact(&mut len_buf)?;
            let data_len = u32::from_le_bytes(len_buf);

            let mut flag = [0u8; 1];
            file.read_exact(&mut flag)?;

            if current_key == fixed_key {
                file.seek(SeekFrom::Current(data_len as i64))?;
                return Ok(Some(flag[0]));
            }

            file.seek(SeekFrom::Current(data_len as i64))?;
        }

        Ok(None)
    }

    fn is_directory(&self, key: &[u8]) -> Result<bool> {
        Ok(matches!(self.get_metadata(key)?, Some(DIRECTORY_FLAG)))
    }

    fn resolve_path(&self, path: &str) -> Result<Vec<u8>> {
        let (is_absolute, components) = self.parse_path(path)?;
        let mut stack = if is_absolute {
            VecDeque::new()
        } else {
            self.split_components(&self.path)
        };

        for component in components {
            match component {
                b"." => continue,
                b".." => {
                    if !stack.is_empty() {
                        stack.pop_back();
                    }
                }
                _ => stack.push_back(component),
            }
        }

        Self::build_key(stack)
    }

    fn parse_path(&self, path: &str) -> Result<(bool, Vec<&[u8]>)> {
        if path.contains("//") || path.chars().any(|c| c.is_control()) {
            return Err(StorageError::InvalidPath);
        }

        let is_absolute = path.starts_with('/');
        let components: Vec<&[u8]> = path.split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes())
            .collect();

        Ok((is_absolute, components))
    }

    fn split_components(&self, path: &[u8]) -> VecDeque<&[u8]> {
        let mut components = VecDeque::new();
        let mut start = 0;

        for (i, &b) in path.iter().enumerate() {
            if b == SEPARATOR {
                if start < i {
                    components.push_back(&path[start..i]);
                }
                start = i + 1;
            }
        }

        if start < path.len() {
            components.push_back(&path[start..]);
        }

        components
    }

    fn build_key(components: VecDeque<&[u8]>) -> Result<Vec<u8>> {
        let mut key = Vec::with_capacity(KEY_SIZE);
        for component in components {
            if component.is_empty() || component.contains(&SEPARATOR) {
                return Err(StorageError::InvalidPath);
            }

            key.extend_from_slice(component);
            key.push(SEPARATOR);
            if key.len() > KEY_SIZE {
                return Err(StorageError::KeyTooLong);
            }
        }
        Ok(key)
    }

    fn parent_path(&self, path: &[u8]) -> Result<Vec<u8>> {
        let mut components = self.split_components(path);
        if components.is_empty() {
            return Ok(Vec::new());
        }

        components.pop_back();
        Self::build_key(components)
    }

    fn key_exists(&self, key: &[u8]) -> Result<bool> {
        Ok(self.get_metadata(key)?.is_some())
    }

    fn with_path(&self, path: Vec<u8>) -> Self {
        Self {
            file: Arc::clone(&self.file),
            path,
        }
    }

    fn validate_key_length(&self, key: &[u8]) -> Result<()> {
        if key.len() > KEY_SIZE {
            Err(StorageError::KeyTooLong)
        } else {
            Ok(())
        }
    }

    fn fixed_key(key: &[u8]) -> [u8; KEY_SIZE] {
        let mut fixed = [0u8; KEY_SIZE];
        let len = key.len().min(KEY_SIZE);
        fixed[..len].copy_from_slice(&key[..len]);
        fixed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_file() -> NamedTempFile {
        NamedTempFile::new().unwrap()
    }

    #[test]
    fn test_create_nested_directories() {
        let file = create_test_file();
        let storage = Storage::open(file.path()).unwrap();

        storage.create_dir_all("/a/b/c").unwrap();
        
        assert!(storage.open_dir("/a").unwrap().is_some());
        assert!(storage.open_dir("/a/b").unwrap().is_some());
        assert!(storage.open_dir("/a/b/c").unwrap().is_some());
    }

    #[test]
    fn test_read_write_files() {
        let file = create_test_file();
        let storage = Storage::open(file.path()).unwrap();

        storage.create_dir_all("/data").unwrap();
        storage.write_file("/data/test.txt", b"hello").unwrap();

        let content = storage.read_file("/data/test.txt").unwrap();
        assert_eq!(content, Some(b"hello".to_vec()));

        storage.write_file("/data/test.txt", b"world").unwrap();
        let content = storage.read_file("/data/test.txt").unwrap();
        assert_eq!(content, Some(b"world".to_vec()));
    }

    #[test]
    fn test_relative_paths() {
        let file = create_test_file();
        let storage = Storage::open(file.path()).unwrap();

        let base = storage.create_dir_all("/base").unwrap();
        let sub = base.create_dir_all("sub").unwrap();

        sub.write_file("file.txt", b"test").unwrap();
        assert_eq!(
            storage.read_file("/base/sub/file.txt").unwrap(),
            Some(b"test".to_vec())
        );
    }

    #[test]
    fn test_invalid_paths() {
        let file = create_test_file();
        let storage = Storage::open(file.path()).unwrap();

        assert!(matches!(
            storage.create_dir_all("invalid//path"),
            Err(StorageError::InvalidPath)
        ));

        assert!(matches!(
            storage.create_dir_all("a/../b"),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn test_remove_entries() {
        let file = create_test_file();
        let storage = Storage::open(file.path()).unwrap();

        storage.create_dir_all("/temp").unwrap();
        storage.write_file("/temp/file", b"data").unwrap();
        
        storage.remove("/temp/file").unwrap();
        assert!(storage.read_file("/temp/file").unwrap().is_none());

        storage.remove("/temp").unwrap();
        assert!(storage.open_dir("/temp").unwrap().is_none());
    }
}
