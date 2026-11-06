use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum OutcomeError {
    Unsupported,
}

impl fmt::Display for OutcomeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("outcome error")
    }
}

impl Error for OutcomeError {}
