use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CodecError {
    Unsupported,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("codec error")
    }
}

impl Error for CodecError {}
