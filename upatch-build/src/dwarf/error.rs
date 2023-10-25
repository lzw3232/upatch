use std::result;
use std::{
    fmt::{self, Debug},
    io,
};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Gimli(gimli::Error),
    Object(object::read::Error),
    Io,
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::Gimli(err)
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::Io
    }
}

impl From<object::read::Error> for Error {
    fn from(err: object::read::Error) -> Self {
        Error::Object(err)
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}
