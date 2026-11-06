use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ModelError {
    Unsupported,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model error")
    }
}

impl Error for ModelError {}
