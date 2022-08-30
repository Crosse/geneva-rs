use std::fmt;

/// `Result` is a type that represents either success ([`Ok`](Self::Ok)) or failure ([`Err`](Self::Err)).
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for Geneva operations.
#[derive(Debug, Clone)]
pub enum Error {
    /// An error parsing a Geneva rule.
    Parse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            Parse(s) => write!(f, "parse error: \"{}\"", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(_) => None,
        }
    }
}
