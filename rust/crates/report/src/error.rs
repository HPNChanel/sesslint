use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ReportError {
    Unsupported,
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("report error")
    }
}

impl Error for ReportError {}
