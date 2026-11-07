use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum RepairError {
    Unsupported,
}

impl fmt::Display for RepairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repair error")
    }
}

impl Error for RepairError {}
