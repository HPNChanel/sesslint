use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ChecksError {
    Unsupported,
}

impl fmt::Display for ChecksError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("checks error")
    }
}

impl Error for ChecksError {}
