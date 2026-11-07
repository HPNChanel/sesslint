use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum SupportError {
    Unsupported,
}

impl fmt::Display for SupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("support error")
    }
}

impl Error for SupportError {}
