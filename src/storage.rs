use core::fmt;
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const KEY_SIZE: usize = 32;

pub struct StorageEntry {
    key: [u8; KEY_SIZE],
    value_len: u32,
    value: Vec<u8>,
    is_deleted: bool,
}

pub struct Storage {
    file: File,
}

#[derive(Debug)]
pub enum StorageError {
    IoError(io::Error),
    KeyTooLong,
    InvalidData,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "IO error: {}", e),
            StorageError::KeyTooLong => write!(f, "Key length exceeds {} bytes", KEY_SIZE),
            StorageError::InvalidData => write!(f, "Invalid data format"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            StorageError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(err: io::Error) -> StorageError {
        StorageError::IoError(err)
    }
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;

impl Storage {
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!path.as_ref().exists())
            .open(path)?;

        Ok(Self { file })
    }

    pub fn write_str(&mut self, key: &str, value: &str) -> StorageResult<()> {
        self.write(key.as_bytes(), value.as_bytes())
    }

    pub fn write(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        if key.len() > KEY_SIZE {
            return Err(StorageError::KeyTooLong);
        }

        let mut fixed_key = [0u8; KEY_SIZE];
        fixed_key[..key.len()].copy_from_slice(key);

        let entry = StorageEntry {
            key: fixed_key,
            value_len: value.len() as u32,
            value: value.to_vec(),
            is_deleted: false,
        };

        self.file.seek(SeekFrom::End(0))?;

        self.file.write_all(&entry.key)?;
        self.file.write_all(&entry.value_len.to_le_bytes())?;
        self.file
            .write_all(&[if entry.is_deleted { 1 } else { 0 }])?;
        self.file.write_all(&entry.value)?;

        self.file.flush()?;

        Ok(())
    }

    pub fn read_str(&mut self, key: &str) -> StorageResult<Option<String>> {
        self.read(key.as_bytes()).map(|opt_vec| {
            opt_vec.map(|vec| String::from_utf8_lossy(&vec).into_owned())
        })
    }

    pub fn read(&mut self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let mut search_key = [0u8; KEY_SIZE];
        search_key[..key.len()].copy_from_slice(key);

        self.file.seek(SeekFrom::Start(0))?;

        let mut latest_value: Option<Vec<u8>> = None;

        loop {
            let mut current_key = [0u8; KEY_SIZE];
            match self.file.read_exact(&mut current_key) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            let mut len_bytes = [0u8; 4];
            self.file
                .read_exact(&mut len_bytes)
                .map_err(|_| StorageError::InvalidData)?;
            let value_len = u32::from_le_bytes(len_bytes);

            let mut deleted_byte = [0u8; 1];
            self.file
                .read_exact(&mut deleted_byte)
                .map_err(|_| StorageError::InvalidData)?;
            let is_deleted = deleted_byte[0] == 1;

            let mut value = vec![0u8; value_len as usize];
            self.file
                .read_exact(&mut value)
                .map_err(|_| StorageError::InvalidData)?;

            if current_key == search_key {
                if !is_deleted {
                    latest_value = Some(value);
                } else {
                    latest_value = None;
                }
            }
        }

        Ok(latest_value)
    }

    pub fn delete_str(&mut self, key: &str) -> StorageResult<()> {
        self.delete(key.as_bytes())
    }

    pub fn delete(&mut self, key: &[u8]) -> StorageResult<()> {
        let mut search_key = [0u8; KEY_SIZE];
        search_key[..key.len()].copy_from_slice(key);

        let entry = StorageEntry {
            key: search_key,
            value_len: 0,
            value: vec![],
            is_deleted: true,
        };

        self.file.seek(SeekFrom::End(0))?;

        self.file.write_all(&entry.key)?;
        self.file.write_all(&entry.value_len.to_le_bytes())?;
        self.file.write_all(&[1])?;

        self.file.flush()?;

        Ok(())
    }
}
