use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum AdaptersError {
    Unsupported,
}

impl fmt::Display for AdaptersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("adapters error")
    }
}

impl Error for AdaptersError {}
