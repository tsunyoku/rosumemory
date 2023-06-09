use std::str::FromStr;
use sysinfo::Pid;
use thiserror::Error;

use crate::memory::read::find_os_pattern;

#[derive(PartialEq, Eq)]
pub enum PatternByte {
    Byte(u8),
    Any,
}

impl FromStr for PatternByte {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "??" => Ok(Self::Any),
            _ => {
                let byte = u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
                Ok(Self::Byte(byte))
            }
        }
    }
}

impl PartialEq<u8> for PatternByte {
    fn eq(&self, other: &u8) -> bool {
        match self {
            Self::Byte(byte) => byte == other,
            Self::Any => true,
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<PatternByte>,
}

impl Pattern {
    fn new(bytes: Vec<PatternByte>) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[PatternByte] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl FromStr for Pattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut aob: Vec<PatternByte> = Vec::new();

        for chunk in s.split_ascii_whitespace() {
            aob.push(PatternByte::from_str(chunk)?);
        }

        Ok(Self::new(aob))
    }
}

impl PartialEq<[u8]> for Pattern {
    fn eq(&self, other: &[u8]) -> bool {
        Iterator::zip(self.bytes.iter(), other.iter()).all(|(a, b)| a == b)
    }
}

impl PartialEq<Vec<u8>> for Pattern {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self == other.as_slice()
    }
}

#[derive(Error, Debug)]
pub enum PatternScanError {
    #[error("pattern not found")]
    NotFound,
    #[error("unknown err: {0}")]
    Unknown(String),
}

// TODO: move this to memory/pattern.rs?
pub fn find_pattern(pid: Pid, pattern_string: &str) -> Result<*mut u8, PatternScanError> {
    let pattern = Pattern::from_str(pattern_string).map_err(PatternScanError::Unknown)?;
    find_os_pattern(pid, pattern)
}
