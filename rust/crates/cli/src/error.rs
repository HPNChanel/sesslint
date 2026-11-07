use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CliError {
    Unsupported,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cli error")
    }
}

impl Error for CliError {}
