use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::os::unix::prelude::OsStrExt as UnixOsStrExt;

/* Contains */
pub trait OsStrContains
where
    Self: AsRef<OsStr>,
{
    fn contains<S: AsRef<[u8]>>(&self, other: S) -> bool {
        let needle = other.as_ref();

        std::os::unix::prelude::OsStrExt::as_bytes(self.as_ref())
            .windows(needle.len())
            .any(|window| window == needle)
    }
}

impl OsStrContains for OsStr {}
impl OsStrContains for OsString {}
impl OsStrContains for Path {}
impl OsStrContains for PathBuf {}

/* Concat */
pub trait OsStrConcat {
    fn concat<T: AsRef<OsStr>>(&mut self, s: T) -> &mut Self;
}

impl OsStrConcat for OsString {
    fn concat<T: AsRef<OsStr>>(&mut self, s: T) -> &mut Self {
        self.push(s);
        self
    }
}

/* UTF-8 */
mod utf8 {
    pub const CHAR_MAX_WIDTH: usize = std::mem::size_of::<char>();

    #[inline]
    pub const fn char_width(b: u8) -> usize {
        // https://tools.ietf.org/html/rfc3629
        const UTF8_CHAR_WIDTH: &[usize; 256] = &[
            // 1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 1
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 2
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 3
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 7
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 8
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 9
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // A
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // B
            0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // C
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // D
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // E
            4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // F
        ];
        UTF8_CHAR_WIDTH[b as usize]
    }
}

/* OsStrCharIndices */
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum CharByteIndex {
    Char(usize, char),
    Byte(usize, u8),
}

impl CharByteIndex {
    pub fn char(&self) -> char {
        match self {
            CharByteIndex::Char(_, c) => *c,
            CharByteIndex::Byte(_, b) => *b as char,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CharByteIndices<'a> {
    char_bytes: &'a [u8],
    front_idx: usize,
    back_idx: usize,
}

impl Iterator for CharByteIndices<'_> {
    type Item = CharByteIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let data = &self.char_bytes[self.front_idx..];
        if data.is_empty() {
            return None;
        }

        let char_len = std::cmp::min(utf8::char_width(data[0]), data.len());
        let char_buf = &data[..char_len];

        match String::from_utf8_lossy(char_buf).chars().next() {
            Some(c) if c != char::REPLACEMENT_CHARACTER => {
                let result = Some(CharByteIndex::Char(self.front_idx, c));
                self.front_idx += char_len;
                result
            }
            _ => {
                let result = Some(CharByteIndex::Byte(self.front_idx, data[0]));
                self.front_idx += 1;
                result
            }
        }
    }
}

impl DoubleEndedIterator for CharByteIndices<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        #[inline]
        fn last_utf8_char_index(data: &[u8]) -> (usize, usize) {
            let data_len = data.len();
            let mut char_len = std::cmp::min(utf8::CHAR_MAX_WIDTH, data_len);

            // Try to match next utf-8 character
            while char_len > 0 {
                let char_idx = data_len - char_len;
                if utf8::char_width(data[char_idx]) == char_len {
                    return (char_idx, char_len);
                }
                char_len -= 1;
            }
            (data_len - 1, 1)
        }

        let data = &self.char_bytes[..self.back_idx];
        if data.is_empty() {
            return None;
        }

        let (char_idx, char_len) = last_utf8_char_index(data);
        let char_buf = &data[char_idx..];

        match String::from_utf8_lossy(char_buf).chars().next() {
            Some(c) if c != char::REPLACEMENT_CHARACTER => {
                self.back_idx -= char_len;
                Some(CharByteIndex::Char(self.back_idx, c))
            }
            _ => {
                self.back_idx -= 1;
                Some(CharByteIndex::Byte(self.back_idx, data[data.len() - 1]))
            }
        }
    }
}

impl<'a> From<&'a [u8]> for CharByteIndices<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self {
            char_bytes: bytes,
            front_idx: 0,
            back_idx: bytes.len(),
        }
    }
}

/* Searcher & ReverseSearcher */
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum SearchStep {
    Match(usize, usize), // (start index, end index)
    Reject(usize, usize),
    Done,
}

pub trait Searcher<'a> {
    fn haystack(&self) -> &'a [u8];

    fn next(&mut self) -> SearchStep;

    #[inline]
    fn next_match(&mut self) -> Option<(usize, usize)> {
        loop {
            match self.next() {
                SearchStep::Match(a, b) => return Some((a, b)),
                SearchStep::Done => return None,
                _ => continue,
            }
        }
    }

    #[inline]
    fn next_reject(&mut self) -> Option<(usize, usize)> {
        loop {
            match self.next() {
                SearchStep::Reject(a, b) => return Some((a, b)),
                SearchStep::Done => return None,
                _ => continue,
            }
        }
    }
}

pub trait ReverseSearcher<'a>: Searcher<'a> {
    fn next_back(&mut self) -> SearchStep;

    #[inline]
    fn next_match_back(&mut self) -> Option<(usize, usize)> {
        loop {
            match self.next_back() {
                SearchStep::Match(a, b) => return Some((a, b)),
                SearchStep::Done => return None,
                _ => continue,
            }
        }
    }

    #[inline]
    fn next_reject_back(&mut self) -> Option<(usize, usize)> {
        loop {
            match self.next_back() {
                SearchStep::Reject(a, b) => return Some((a, b)),
                SearchStep::Done => return None,
                _ => continue,
            }
        }
    }
}

/* CharLiteralSearcher */
#[derive(Clone, Debug)]
pub struct CharLiteralSearcher<'a> {
    indices: CharByteIndices<'a>,
    literal: char,
}

impl<'a> CharLiteralSearcher<'a> {
    fn new(haystack: &'a [u8], literal: char) -> Self {
        Self {
            indices: CharByteIndices::from(haystack),
            literal,
        }
    }
}

impl<'a> Searcher<'a> for CharLiteralSearcher<'a> {
    fn haystack(&self) -> &'a [u8] {
        self.indices.char_bytes
    }

    fn next(&mut self) -> SearchStep {
        match self.indices.next() {
            Some(CharByteIndex::Char(char_idx, c)) => {
                let new_idx = char_idx + c.len_utf8();
                match self.literal == c {
                    true => SearchStep::Match(char_idx, new_idx),
                    false => SearchStep::Reject(char_idx, new_idx),
                }
            }
            Some(CharByteIndex::Byte(byte_idx, b)) => {
                let new_idx = byte_idx + 1;
                match self.literal == (b as char) {
                    true => SearchStep::Match(byte_idx, new_idx),
                    false => SearchStep::Reject(byte_idx, new_idx),
                }
            }
            None => SearchStep::Done,
        }
    }
}

impl<'a> ReverseSearcher<'a> for CharLiteralSearcher<'a> {
    fn next_back(&mut self) -> SearchStep {
        match self.indices.next_back() {
            Some(CharByteIndex::Char(char_idx, c)) => {
                let new_idx = char_idx + c.len_utf8();
                match self.literal == c {
                    true => SearchStep::Match(char_idx, new_idx),
                    false => SearchStep::Reject(char_idx, new_idx),
                }
            }
            Some(CharByteIndex::Byte(byte_idx, b)) => {
                let new_idx = byte_idx + 1;
                match self.literal == (b as char) {
                    true => SearchStep::Match(byte_idx, new_idx),
                    false => SearchStep::Reject(byte_idx, new_idx),
                }
            }
            None => SearchStep::Done,
        }
    }
}

/* CharPredicateSearcher */
#[derive(Clone, Debug)]
pub struct CharPredicateSearcher<'a, P> {
    indices: CharByteIndices<'a>,
    predicate: P,
}

impl<'a, P: FnMut(char) -> bool> CharPredicateSearcher<'a, P> {
    fn new(haystack: &'a [u8], predicate: P) -> Self {
        Self {
            indices: CharByteIndices::from(haystack),
            predicate,
        }
    }
}

impl<'a, P: FnMut(char) -> bool> Searcher<'a> for CharPredicateSearcher<'a, P> {
    fn haystack(&self) -> &'a [u8] {
        self.indices.char_bytes
    }

    fn next(&mut self) -> SearchStep {
        match self.indices.next() {
            Some(CharByteIndex::Char(char_idx, c)) => {
                let new_idx = char_idx + c.len_utf8();
                match (self.predicate)(c) {
                    true => SearchStep::Match(char_idx, new_idx),
                    false => SearchStep::Reject(char_idx, new_idx),
                }
            }
            Some(CharByteIndex::Byte(byte_idx, b)) => {
                let new_idx = byte_idx + 1;
                match (self.predicate)(b as char) {
                    true => SearchStep::Match(byte_idx, new_idx),
                    false => SearchStep::Reject(byte_idx, new_idx),
                }
            }
            None => SearchStep::Done,
        }
    }
}

impl<'a, P: FnMut(char) -> bool> ReverseSearcher<'a> for CharPredicateSearcher<'a, P> {
    fn next_back(&mut self) -> SearchStep {
        match self.indices.next_back() {
            Some(CharByteIndex::Char(char_idx, c)) => {
                let new_idx = char_idx + c.len_utf8();
                match (self.predicate)(c) {
                    true => SearchStep::Match(char_idx, new_idx),
                    false => SearchStep::Reject(char_idx, new_idx),
                }
            }
            Some(CharByteIndex::Byte(byte_idx, b)) => {
                let new_idx = byte_idx + 1;
                match (self.predicate)(b as char) {
                    true => SearchStep::Match(byte_idx, new_idx),
                    false => SearchStep::Reject(byte_idx, new_idx),
                }
            }
            None => SearchStep::Done,
        }
    }
}

/* OsStrSearcher */
#[derive(Clone, Debug)]
pub struct OsStrSearcher<'a, T> {
    indices: CharByteIndices<'a>,
    needle: T,
    match_fw: bool,
    match_bw: bool,
}

impl<'a, T> OsStrSearcher<'a, T> {
    fn new(haystack: &'a [u8], needle: T) -> Self {
        Self {
            indices: CharByteIndices::from(haystack),
            needle,
            match_fw: false,
            match_bw: false,
        }
    }
}

impl<'a, T: AsRef<OsStr>> Searcher<'a> for OsStrSearcher<'a, T> {
    fn haystack(&self) -> &'a [u8] {
        self.indices.char_bytes
    }

    fn next(&mut self) -> SearchStep {
        let haystack: &mut CharByteIndices = &mut self.indices;
        let needle = &mut CharByteIndices::from(self.needle.as_ref().as_bytes());

        let front_idx = haystack.front_idx;

        if needle.char_bytes.is_empty() {
            // Case 1: Needle is empty, rejects every char and matches every empty string between them
            self.match_fw = !self.match_fw;
            if self.match_fw {
                return SearchStep::Match(front_idx, front_idx);
            }
            match haystack.next() {
                Some(_) => {
                    return SearchStep::Reject(front_idx, haystack.front_idx);
                }
                None => {
                    return SearchStep::Done;
                }
            }
        }

        // Compare every chars in needle with haystack in sequence
        for needle_char in needle.by_ref() {
            if let Some(haystack_char) = haystack.next() {
                if haystack_char.char() != needle_char.char() {
                    // Case 2: Char mismatched, stop matching, reject matched chars
                    return SearchStep::Reject(front_idx, haystack.front_idx);
                }
                continue;
            }
            let bytes_left = haystack.char_bytes.len() - haystack.front_idx;
            if bytes_left != 0 {
                // Case 3: Haystack is empty, but needle has chars left, reject left chars in haystack
                return SearchStep::Reject(front_idx, front_idx + bytes_left);
            }
            // Case 4: Haystack has nothing left, search done
            return SearchStep::Done;
        }
        // Case 5: All chars in neelde are matched
        SearchStep::Match(front_idx, haystack.front_idx)
    }
}

impl<'a, T: AsRef<OsStr>> ReverseSearcher<'a> for OsStrSearcher<'a, T> {
    fn next_back(&mut self) -> SearchStep {
        let haystack = &mut self.indices;
        let needle = &mut CharByteIndices::from(self.needle.as_ref().as_bytes());

        let back_idx = haystack.back_idx;

        if needle.char_bytes.is_empty() {
            // Case 1: Needle is empty, rejects every char and matches every empty string between them
            self.match_bw = !self.match_bw;
            if self.match_bw {
                return SearchStep::Match(back_idx, back_idx);
            }
            match haystack.next_back() {
                Some(_) => {
                    return SearchStep::Reject(haystack.back_idx, back_idx);
                }
                None => {
                    return SearchStep::Done;
                }
            }
        }

        // Compare every chars in needle with haystack in sequence
        while let Some(needle_char) = needle.next_back() {
            if let Some(haystack_char) = haystack.next_back() {
                if haystack_char.char() != needle_char.char() {
                    // Case 2: Char mismatched, stop matching, reject matched chars
                    return SearchStep::Reject(haystack.back_idx, back_idx);
                }
                continue;
            }
            if haystack.back_idx != 0 {
                // Case 3: Haystack is empty, but needle has chars left, reject left chars in haystack
                return SearchStep::Reject(0, back_idx);
            }
            // Case 4: Haystack has nothing left, search done
            return SearchStep::Done;
        }
        // Case 5: All chars in neelde are matched
        SearchStep::Match(haystack.back_idx, back_idx)
    }
}

/* Pattern */
pub trait Pattern<'a> {
    type Searcher: Searcher<'a>;
    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher;
}

impl<'a> Pattern<'a> for char {
    type Searcher = CharLiteralSearcher<'a>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        CharLiteralSearcher::new(haystack, self)
    }
}

impl<'a> Pattern<'a> for String {
    type Searcher = OsStrSearcher<'a, Self>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        OsStrSearcher::new(haystack, self)
    }
}

impl<'a> Pattern<'a> for &'a String {
    type Searcher = OsStrSearcher<'a, Self>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        OsStrSearcher::new(haystack, self)
    }
}

impl<'a> Pattern<'a> for &'a str {
    type Searcher = OsStrSearcher<'a, Self>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        OsStrSearcher::new(haystack, self)
    }
}

impl<'a> Pattern<'a> for OsString {
    type Searcher = OsStrSearcher<'a, Self>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        OsStrSearcher::new(haystack, self)
    }
}

impl<'a> Pattern<'a> for &'a OsString {
    type Searcher = OsStrSearcher<'a, Self>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        OsStrSearcher::new(haystack, self)
    }
}

impl<'a> Pattern<'a> for &'a OsStr {
    type Searcher = OsStrSearcher<'a, Self>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        OsStrSearcher::new(haystack, self)
    }
}

impl<'a, P: FnMut(char) -> bool> Pattern<'a> for P {
    type Searcher = CharPredicateSearcher<'a, P>;

    fn into_searcher(self, haystack: &'a [u8]) -> Self::Searcher {
        CharPredicateSearcher::new(haystack, self)
    }
}

#[derive(Clone, Debug)]
pub struct Split<'a, P: Pattern<'a>> {
    searcher: P::Searcher,
    position: usize,
    finished: bool,
}

impl<'a, P: Pattern<'a>> Iterator for Split<'a, P> {
    type Item = &'a OsStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.searcher.next_match() {
            Some((matched_idx, new_idx)) => {
                let match_result = Some(OsStr::from_bytes(
                    &self.searcher.haystack()[self.position..matched_idx],
                ));
                self.position = new_idx;
                match_result
            }
            None => {
                let match_result = Some(OsStr::from_bytes(
                    &self.searcher.haystack()[self.position..],
                ));

                self.finished = true;
                match_result
            }
        }
    }
}

/* OsStrExt */
pub trait OsStrExt: AsRef<OsStr> {
    fn is_char_boundary(&self, index: usize) -> bool {
        let haystack = self.as_ref().as_bytes();
        if index == 0 {
            return true;
        }
        match haystack.get(index) {
            Some(&b) => {
                // This is bit magic equivalent to: b < 128 || b >= 192
                b as i8 >= -0x40
            }
            None => index == haystack.len(),
        }
    }

    fn char_indices(&self) -> CharByteIndices<'_> {
        CharByteIndices::from(self.as_ref().as_bytes())
    }

    fn find<'a, P: Pattern<'a>>(&'a self, pat: P) -> Option<usize> {
        pat.into_searcher(self.as_ref().as_bytes())
            .next_match()
            .map(|(i, _)| i)
    }

    fn contains<'a, P: Pattern<'a>>(&'a self, pat: P) -> bool {
        self.find(pat).is_some()
    }

    fn starts_with<'a, P: Pattern<'a>>(&'a self, pat: P) -> bool {
        matches!(
            pat.into_searcher(self.as_ref().as_bytes()).next(),
            SearchStep::Match(0, _)
        )
    }

    fn ends_with<'a, P>(&'a self, pat: P) -> bool
    where
        P: Pattern<'a>,
        P::Searcher: ReverseSearcher<'a>,
    {
        let haystack = self.as_ref().as_bytes();
        matches!(
            pat.into_searcher(haystack).next_back(),
            SearchStep::Match(_, j) if haystack.len() == j
        )
    }

    fn strip_prefix<'a, P: Pattern<'a>>(&'a self, pat: P) -> Option<&'a OsStr> {
        let haystack = self.as_ref().as_bytes();
        match pat.into_searcher(haystack).next() {
            SearchStep::Match(start, end) => {
                debug_assert_eq!(start, 0);
                Some(OsStr::from_bytes(&haystack[end..]))
            }
            _ => None,
        }
    }

    fn strip_suffix<'a, P>(&'a self, pat: P) -> Option<&'a OsStr>
    where
        P: Pattern<'a>,
        P::Searcher: ReverseSearcher<'a>,
    {
        let haystack = self.as_ref().as_bytes();
        match pat.into_searcher(haystack).next_back() {
            SearchStep::Match(start, end) => {
                debug_assert_eq!(end, haystack.len());
                Some(OsStr::from_bytes(&haystack[..start]))
            }
            _ => None,
        }
    }

    fn split<'a, P: Pattern<'a>>(&'a self, pat: P) -> Split<P> {
        Split {
            searcher: pat.into_searcher(self.as_ref().as_bytes()),
            position: 0,
            finished: false,
        }
    }

    fn split_at(&self, mid: usize) -> (&OsStr, &OsStr) {
        if !self.is_char_boundary(mid) {
            panic!("failed to slice osstring");
        }
        let (lhs, rhs) = self.as_ref().as_bytes().split_at(mid);
        (OsStr::from_bytes(lhs), OsStr::from_bytes(rhs))
    }

    fn trim_start_matches<'a, P: Pattern<'a>>(&'a self, pat: P) -> &'a OsStr {
        let haystack = self.as_ref().as_bytes();
        let start = match pat.into_searcher(haystack).next_reject() {
            Some((a, _)) => a,
            None => haystack.len(),
        };
        OsStr::from_bytes(&haystack[start..])
    }

    fn trim_end_matches<'a, P>(&'a self, pat: P) -> &'a OsStr
    where
        P: Pattern<'a>,
        P::Searcher: ReverseSearcher<'a>,
    {
        let haystack = self.as_ref().as_bytes();
        let end = match pat.into_searcher(haystack).next_reject_back() {
            Some((_, b)) => b,
            None => 0,
        };
        OsStr::from_bytes(&haystack[..end])
    }

    fn trim_matches<'a, P>(&'a self, pat: P) -> &'a OsStr
    where
        P: Pattern<'a>,
        P::Searcher: ReverseSearcher<'a>,
    {
        let haystack = self.as_ref().as_bytes();
        let mut start = 0;
        let mut end = 0;
        let mut matcher = pat.into_searcher(haystack);

        if let Some((a, b)) = matcher.next_reject() {
            start = a;
            end = b;
        }

        if let Some((_, b)) = matcher.next_reject_back() {
            end = b;
        }

        OsStr::from_bytes(&haystack[start..end])
    }

    fn trim(&self) -> &OsStr {
        self.trim_matches(char::is_whitespace)
    }

    fn trim_start(&self) -> &OsStr {
        self.trim_start_matches(char::is_whitespace)
    }

    fn trim_end(&self) -> &OsStr {
        self.trim_end_matches(char::is_whitespace)
    }
}

impl OsStrExt for OsStr {}

/* OsStringExt */
pub trait OsStringExt {
    fn concat<S: AsRef<OsStr>>(self, s: S) -> Self;
    fn append<S: AsRef<OsStr>>(self, s: S) -> Self;
}

impl OsStringExt for OsString {
    #[inline]
    fn concat<S: AsRef<OsStr>>(mut self, s: S) -> Self {
        self.push(s);
        self
    }

    #[inline]
    fn append<S: AsRef<OsStr>>(mut self, s: S) -> Self {
        if (self.len() != 0) && (!self.ends_with(char::is_whitespace)) {
            self.push(" ");
        }
        self.push(s);
        self
    }
}

#[test]
fn test_os_str_ext() {
    let old_str = "\t\tThe\tquick\tbrown\tfox\tjumps\tover\ta\tlazy\tdog\nGrüße, Jürgen ❤\r\n\0";
    let test_str = OsStr::new(old_str);

    let pattern0 = "T";
    let pattern1 = "fox";
    let pattern2 = "slow";
    let pattern3 = "\t";
    let pattern4 = '\t';
    let pattern5 = '\0';
    let pattern6 = '\r';
    let pattern7 = "";
    let pattern8 = |c: char| c.is_ascii_control();
    let pattern9 = char::is_whitespace;

    println!("Testing OsStrExt::is_char_boundary()...");
    for index in 0..old_str.as_bytes().len() {
        assert_eq!(
            old_str.is_char_boundary(index),
            test_str.is_char_boundary(index)
        );
    }

    println!("Testing OsStrExt::char_indices()...");
    assert_eq!(
        old_str.char_indices().collect::<Vec<_>>(),
        test_str
            .char_indices()
            .map(|c| match c {
                CharByteIndex::Char(len, c) => (len, c),
                CharByteIndex::Byte(len, b) => (len, b as char),
            })
            .collect::<Vec<_>>()
    );

    println!("Testing OsStrExt::lines()...");
    assert_eq!(
        old_str.lines().map(OsString::from).collect::<Vec<_>>(),
        test_str.lines().filter_map(|s| s.ok()).collect::<Vec<_>>()
    );

    println!("Testing OsStrExt::find()...");
    assert_eq!(old_str.find(pattern0), test_str.find(pattern0));
    assert_eq!(old_str.find(pattern1), test_str.find(pattern1));
    assert_eq!(old_str.find(pattern2), test_str.find(pattern2));
    assert_eq!(old_str.find(pattern3), test_str.find(pattern3));
    assert_eq!(old_str.find(pattern4), test_str.find(pattern4));
    assert_eq!(old_str.find(pattern5), test_str.find(pattern5));
    assert_eq!(old_str.find(pattern6), test_str.find(pattern6));
    assert_eq!(old_str.find(pattern7), test_str.find(pattern7));
    assert_eq!(old_str.find(pattern8), test_str.find(pattern8));
    assert_eq!(old_str.find(pattern9), test_str.find(pattern9));

    println!("Testing OsStrExt::contains()...");
    assert_eq!(old_str.contains(pattern0), test_str.contains(pattern0));
    assert_eq!(old_str.contains(pattern1), test_str.contains(pattern1));
    assert_eq!(old_str.contains(pattern2), test_str.contains(pattern2));
    assert_eq!(old_str.contains(pattern3), test_str.contains(pattern3));
    assert_eq!(old_str.contains(pattern4), test_str.contains(pattern4));
    assert_eq!(old_str.contains(pattern5), test_str.contains(pattern5));
    assert_eq!(old_str.contains(pattern6), test_str.contains(pattern6));
    assert_eq!(old_str.contains(pattern7), test_str.contains(pattern7));
    assert_eq!(old_str.contains(pattern8), test_str.contains(pattern8));
    assert_eq!(old_str.contains(pattern9), test_str.contains(pattern9));

    println!("Testing OsStrExt::starts_with()...");
    assert_eq!(
        old_str.starts_with(pattern0),
        test_str.starts_with(pattern0)
    );
    assert_eq!(
        old_str.starts_with(pattern1),
        test_str.starts_with(pattern1)
    );
    assert_eq!(
        old_str.starts_with(pattern2),
        test_str.starts_with(pattern2)
    );
    assert_eq!(
        old_str.starts_with(pattern3),
        test_str.starts_with(pattern3)
    );
    assert_eq!(
        old_str.starts_with(pattern4),
        test_str.starts_with(pattern4)
    );
    assert_eq!(
        old_str.starts_with(pattern5),
        test_str.starts_with(pattern5)
    );
    assert_eq!(
        old_str.starts_with(pattern6),
        test_str.starts_with(pattern6)
    );
    assert_eq!(
        old_str.starts_with(pattern7),
        test_str.starts_with(pattern7)
    );
    assert_eq!(
        old_str.starts_with(pattern8),
        test_str.starts_with(pattern8)
    );
    assert_eq!(
        old_str.starts_with(pattern9),
        test_str.starts_with(pattern9)
    );

    println!("Testing OsStrExt::ends_with()...");
    assert_eq!(old_str.ends_with(pattern0), test_str.ends_with(pattern0));
    assert_eq!(old_str.ends_with(pattern1), test_str.ends_with(pattern1));
    assert_eq!(old_str.ends_with(pattern2), test_str.ends_with(pattern2));
    assert_eq!(old_str.ends_with(pattern3), test_str.ends_with(pattern3));
    assert_eq!(old_str.ends_with(pattern4), test_str.ends_with(pattern4));
    assert_eq!(old_str.ends_with(pattern5), test_str.ends_with(pattern5));
    assert_eq!(old_str.ends_with(pattern6), test_str.ends_with(pattern6));
    assert_eq!(old_str.ends_with(pattern7), test_str.ends_with(pattern7));
    assert_eq!(old_str.ends_with(pattern8), test_str.ends_with(pattern8));
    assert_eq!(old_str.ends_with(pattern9), test_str.ends_with(pattern9));

    println!("Testing OsStrExt::strip_prefix()...");
    assert_eq!(
        old_str.strip_prefix(pattern0).map(OsStr::new),
        test_str.strip_prefix(pattern0)
    );
    assert_eq!(
        old_str.strip_prefix(pattern1).map(OsStr::new),
        test_str.strip_prefix(pattern1)
    );
    assert_eq!(
        old_str.strip_prefix(pattern2).map(OsStr::new),
        test_str.strip_prefix(pattern2)
    );
    assert_eq!(
        old_str.strip_prefix(pattern3).map(OsStr::new),
        test_str.strip_prefix(pattern3)
    );
    assert_eq!(
        old_str.strip_prefix(pattern4).map(OsStr::new),
        test_str.strip_prefix(pattern4)
    );
    assert_eq!(
        old_str.strip_prefix(pattern5).map(OsStr::new),
        test_str.strip_prefix(pattern5)
    );
    assert_eq!(
        old_str.strip_prefix(pattern6).map(OsStr::new),
        test_str.strip_prefix(pattern6)
    );
    assert_eq!(
        old_str.strip_prefix(pattern7).map(OsStr::new),
        test_str.strip_prefix(pattern7)
    );
    assert_eq!(
        old_str.strip_prefix(pattern8).map(OsStr::new),
        test_str.strip_prefix(pattern8)
    );
    assert_eq!(
        old_str.strip_prefix(pattern9).map(OsStr::new),
        test_str.strip_prefix(pattern9)
    );

    println!("Testing OsStrExt::strip_suffix()...");
    assert_eq!(
        old_str.strip_suffix(pattern0).map(OsStr::new),
        test_str.strip_suffix(pattern0)
    );
    assert_eq!(
        old_str.strip_suffix(pattern1).map(OsStr::new),
        test_str.strip_suffix(pattern1)
    );
    assert_eq!(
        old_str.strip_suffix(pattern2).map(OsStr::new),
        test_str.strip_suffix(pattern2)
    );
    assert_eq!(
        old_str.strip_suffix(pattern3).map(OsStr::new),
        test_str.strip_suffix(pattern3)
    );
    assert_eq!(
        old_str.strip_suffix(pattern4).map(OsStr::new),
        test_str.strip_suffix(pattern4)
    );
    assert_eq!(
        old_str.strip_suffix(pattern5).map(OsStr::new),
        test_str.strip_suffix(pattern5)
    );
    assert_eq!(
        old_str.strip_suffix(pattern6).map(OsStr::new),
        test_str.strip_suffix(pattern6)
    );
    assert_eq!(
        old_str.strip_suffix(pattern7).map(OsStr::new),
        test_str.strip_suffix(pattern7)
    );
    assert_eq!(
        old_str.strip_suffix(pattern8).map(OsStr::new),
        test_str.strip_suffix(pattern8)
    );
    assert_eq!(
        old_str.strip_suffix(pattern9).map(OsStr::new),
        test_str.strip_suffix(pattern9)
    );

    println!("Testing OsStrExt::trim_start_matches()...");
    assert_eq!(
        old_str.trim_start_matches(pattern0),
        test_str.trim_start_matches(pattern0)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern1),
        test_str.trim_start_matches(pattern1)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern2),
        test_str.trim_start_matches(pattern2)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern3),
        test_str.trim_start_matches(pattern3)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern4),
        test_str.trim_start_matches(pattern4)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern5),
        test_str.trim_start_matches(pattern5)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern6),
        test_str.trim_start_matches(pattern6)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern7),
        test_str.trim_start_matches(pattern7)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern8),
        test_str.trim_start_matches(pattern8)
    );
    assert_eq!(
        old_str.trim_start_matches(pattern9),
        test_str.trim_start_matches(pattern9)
    );

    println!("Testing OsStrExt::trim_end_matches()...");
    assert_eq!(
        old_str.trim_end_matches(pattern0),
        test_str.trim_end_matches(pattern0)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern1),
        test_str.trim_end_matches(pattern1)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern2),
        test_str.trim_end_matches(pattern2)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern3),
        test_str.trim_end_matches(pattern3)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern4),
        test_str.trim_end_matches(pattern4)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern5),
        test_str.trim_end_matches(pattern5)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern6),
        test_str.trim_end_matches(pattern6)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern7),
        test_str.trim_end_matches(pattern7)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern8),
        test_str.trim_end_matches(pattern8)
    );
    assert_eq!(
        old_str.trim_end_matches(pattern9),
        test_str.trim_end_matches(pattern9)
    );

    println!("Testing OsStrExt::trim_matches()...");
    assert_eq!(test_str, test_str.trim_matches(pattern0));
    assert_eq!(test_str, test_str.trim_matches(pattern1));
    assert_eq!(test_str, test_str.trim_matches(pattern2));
    assert_eq!(
        old_str.trim_matches(pattern4),
        test_str.trim_matches(pattern3)
    );
    assert_eq!(
        old_str.trim_matches(pattern4),
        test_str.trim_matches(pattern4)
    );
    assert_eq!(
        old_str.trim_matches(pattern5),
        test_str.trim_matches(pattern5)
    );
    assert_eq!(
        old_str.trim_matches(pattern6),
        test_str.trim_matches(pattern6)
    );
    assert_eq!(test_str, test_str.trim_matches(pattern7));
    assert_eq!(
        old_str.trim_matches(pattern8),
        test_str.trim_matches(pattern8)
    );
    assert_eq!(
        old_str.trim_matches(pattern9),
        test_str.trim_matches(pattern9)
    );

    println!("Testing OsStrExt::trim_start()...");
    assert_eq!(old_str.trim_start(), test_str.trim_start());

    println!("Testing OsStrExt::trim_end()...");
    assert_eq!(old_str.trim_end(), test_str.trim_end());

    println!("Testing OsStrExt::trim()...");
    assert_eq!(old_str.trim(), test_str.trim());

    println!("Testing OsStrExt::split()...");
    assert_eq!(
        old_str.split(pattern0).collect::<Vec<_>>(),
        test_str.split(pattern0).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern1).collect::<Vec<_>>(),
        test_str.split(pattern1).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern2).collect::<Vec<_>>(),
        test_str.split(pattern2).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern3).collect::<Vec<_>>(),
        test_str.split(pattern3).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern4).collect::<Vec<_>>(),
        test_str.split(pattern4).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern5).collect::<Vec<_>>(),
        test_str.split(pattern5).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern6).collect::<Vec<_>>(),
        test_str.split(pattern6).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern7).collect::<Vec<_>>(),
        test_str.split(pattern7).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern8).collect::<Vec<_>>(),
        test_str.split(pattern8).collect::<Vec<_>>()
    );
    assert_eq!(
        old_str.split(pattern9).collect::<Vec<_>>(),
        test_str.split(pattern9).collect::<Vec<_>>()
    );

    println!("Testing OsStrExt::split_at()...");
    for index in 0..old_str.as_bytes().len() {
        if !old_str.is_char_boundary(index) {
            continue;
        }

        let (a, b) = old_str.split_at(index);
        let str_result = (OsStr::new(a), OsStr::new(b));
        let os_str_result = test_str.split_at(index);

        assert_eq!(str_result, os_str_result);
    }

    println!("Testing OsStrExt::split_whitespace()...");
    assert_eq!(
        old_str.split_whitespace().collect::<Vec<_>>(),
        test_str.split_whitespace().collect::<Vec<_>>()
    );
}

#[test]
fn test_os_string_ext() {
    let orig_str0 = "\t\tThe\tquick\tbrown\tfox\tjumps\tover\ta\tlazy\tdog\tGrüße, Jürgen ❤\r\n\0";
    let orig_str1 = "The quick brown fox jumps over a lazy dog";

    println!("Testing OsStringExt::concat()...");
    let mut test_str = OsString::new();
    for s in orig_str0.split("") {
        test_str = test_str.concat(s)
    }
    assert_eq!(orig_str0, test_str);

    println!("Testing OsStringExt::append()...");
    let test_str = OsString::new()
        .append("The")
        .append("quick")
        .append("brown")
        .append("fox")
        .append("jumps")
        .append("over")
        .append("a")
        .append("lazy")
        .append("dog");
    assert_eq!(orig_str1, test_str);
}
