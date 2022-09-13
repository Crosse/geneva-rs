use std::fmt;

use crate::parser;

/// `Result` is a type that represents either success ([`Ok`](Self::Ok)) or failure ([`Err`](Self::Err)).
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for Geneva operations.
#[derive(Debug, Clone)]
pub enum Error {
    /// An error parsing a Geneva rule.
    Parse(String),
    Syntax(pest::error::Error<parser::Rule>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            Parse(s) => write!(f, "parse error: \"{}\"", s),
            Syntax(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(_) => None,
            Self::Syntax(s) => Some(s),
        }
    }
}

impl From<pest::error::Error<parser::Rule>> for Error {
    fn from(e: pest::error::Error<parser::Rule>) -> Self {
        Self::Syntax(e)
    }
}
