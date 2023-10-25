use std::convert::TryInto;

pub trait ReadInteger<T> {
    fn from_le_bytes(data: &[u8]) -> T;
    fn from_be_bytes(data: &[u8]) -> T;

    fn to_le_bytes(data: T) -> Vec<u8>;
    fn to_be_bytes(data: T) -> Vec<u8>;
}

#[derive(Debug, Clone, Copy)]
pub enum Endianness {
    /// Little endian byte order.
    Little,
    /// Big endian byte order.
    Big,
}

#[derive(Debug, Clone, Copy)]
pub struct Endian {
    endian: Endianness,
}

impl Endian {
    pub fn new(endian: Endianness) -> Self {
        Self { endian }
    }

    pub fn read_integer<T: ReadInteger<T>>(&self, data: &[u8]) -> T {
        match self.endian {
            Endianness::Little => T::from_le_bytes(&data[..std::mem::size_of::<T>()]),
            Endianness::Big => T::from_be_bytes(&data[..std::mem::size_of::<T>()]),
        }
    }

    pub fn write_integer<T: ReadInteger<T>>(&self, data: T) -> Vec<u8> {
        match self.endian {
            Endianness::Little => T::to_le_bytes(data),
            Endianness::Big => T::to_be_bytes(data),
        }
    }
}

macro_rules! impl_read_integer {
    ($($t:ty),+) => {
        $(impl ReadInteger<$t> for $t {
            fn from_le_bytes(data: &[u8]) -> $t {
                <$t>::from_le_bytes(data.try_into().unwrap())
            }
            fn from_be_bytes(data: &[u8]) -> $t {
                <$t>::from_be_bytes(data.try_into().unwrap())
            }

            fn to_le_bytes(data: $t) -> Vec<u8> {
                <$t>::to_le_bytes(data).into()
            }
            fn to_be_bytes(data: $t) -> Vec<u8> {
                <$t>::to_be_bytes(data).into()
            }
        })+
    }
}

impl_read_integer!(u8, u16, u32, u64, u128);

pub trait OperateRead {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T;
}

pub trait OperateWrite {
    fn set<T: ReadInteger<T>>(&mut self, start: usize, data: T);
}
