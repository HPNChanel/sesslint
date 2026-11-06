use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum IntegrationsError {
    Unsupported,
}

impl fmt::Display for IntegrationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("integrations error")
    }
}

impl Error for IntegrationsError {}
