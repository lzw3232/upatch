use std::ffi::OsString;
use std::io::BufRead;
use std::os::unix::prelude::OsStringExt;

pub struct RawLines<B> {
    buf: B,
}

impl<B: BufRead> Iterator for RawLines<B> {
    type Item = std::io::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        const CHAR_LF: [u8; 1] = [b'\n'];
        const CHAR_CR: [u8; 1] = [b'\r'];

        let mut buf = Vec::<u8>::new();
        match self.buf.read_until(CHAR_LF[0], &mut buf) {
            Ok(0) => None,
            Ok(_) => {
                // Drop "\n" or "\r\n" on the buf tail
                if buf.ends_with(&CHAR_LF) {
                    buf.pop();
                    if buf.ends_with(&CHAR_CR) {
                        buf.pop();
                    }
                }
                // Drop remaining capacity to save some memory
                buf.shrink_to_fit();
                Some(Ok(OsString::from_vec(buf)))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

impl<B: BufRead> From<B> for RawLines<B> {
    fn from(buf: B) -> Self {
        Self { buf }
    }
}
