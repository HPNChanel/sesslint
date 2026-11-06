use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ScanError {
    Unsupported,
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scan error")
    }
}

impl Error for ScanError {}
