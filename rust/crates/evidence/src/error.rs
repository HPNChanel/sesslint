use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum EvidenceError {
    Unsupported,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("evidence error")
    }
}

impl Error for EvidenceError {}
