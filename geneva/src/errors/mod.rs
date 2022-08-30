use std::fmt;

/// `Result` is a type that represents either success ([`Ok`](Self::Ok)) or failure ([`Err`](Self::Err)).
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for Geneva operations.
#[derive(Debug, Clone)]
pub enum Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error!")
    }
}
