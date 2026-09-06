//! Small bounded JSON subset: objects, arrays, ASCII strings and canonical u63
//! integers. Enrollment has no booleans, nulls, negative numbers or floats.
use super::EnrollmentError as Error;
use std::collections::BTreeMap;

pub(super) enum Value {
    Object(BTreeMap<String, Value>),
    Array(Vec<Value>),
    String(String),
    Integer(i64),
}

impl Value {
    pub(super) fn object(self) -> Result<BTreeMap<String, Self>, Error> {
        match self {
            Self::Object(v) => Ok(v),
            _ => Err(Error),
        }
    }
    pub(super) fn array(self) -> Result<Vec<Self>, Error> {
        match self {
            Self::Array(v) => Ok(v),
            _ => Err(Error),
        }
    }
    pub(super) fn string(self) -> Result<String, Error> {
        match self {
            Self::String(v) => Ok(v),
            _ => Err(Error),
        }
    }
    pub(super) fn integer(self) -> Result<i64, Error> {
        match self {
            Self::Integer(v) => Ok(v),
            _ => Err(Error),
        }
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.is_empty() || bytes.len() > 262_144 {
        return Err(Error);
    }
    let mut parser = Parser {
        bytes,
        index: 0,
        nodes: 0,
    };
    let value = parser.value(0)?;
    parser.space();
    if parser.index != bytes.len() {
        return Err(Error);
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
    nodes: usize,
}
impl Parser<'_> {
    fn space(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.index += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        self.space();
        if self.bytes.get(self.index) == Some(&byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }
    fn next(&mut self) -> Result<u8, Error> {
        let b = *self.bytes.get(self.index).ok_or(Error)?;
        self.index += 1;
        Ok(b)
    }
    fn string(&mut self) -> Result<String, Error> {
        if !self.take(b'"') {
            return Err(Error);
        }
        let mut out = String::new();
        loop {
            let b = self.next()?;
            if b == b'"' {
                return Ok(out);
            }
            let decoded = if b == b'\\' {
                match self.next()? {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        let mut n = 0u16;
                        for _ in 0..4 {
                            n = n * 16
                                + u16::try_from(
                                    char::from(self.next()?).to_digit(16).ok_or(Error)?,
                                )
                                .map_err(|_| Error)?;
                        }
                        u8::try_from(n).map_err(|_| Error)?
                    }
                    _ => return Err(Error),
                }
            } else {
                if !(0x20..=0x7e).contains(&b) {
                    return Err(Error);
                }
                b
            };
            if !decoded.is_ascii() || out.len() >= 256 {
                return Err(Error);
            }
            out.push(char::from(decoded));
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        self.nodes += 1;
        if depth > 5 || self.nodes > 2048 {
            return Err(Error);
        }
        self.space();
        match self.bytes.get(self.index).copied().ok_or(Error)? {
            b'{' => {
                self.index += 1;
                let mut values = BTreeMap::new();
                if self.take(b'}') {
                    return Ok(Value::Object(values));
                }
                loop {
                    let key = self.string()?;
                    if !self.take(b':') || values.len() >= 8 {
                        return Err(Error);
                    }
                    let value = self.value(depth + 1)?;
                    if values.insert(key, value).is_some() {
                        return Err(Error);
                    }
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(Error);
                    }
                }
                Ok(Value::Object(values))
            }
            b'[' => {
                self.index += 1;
                let mut values = Vec::new();
                if self.take(b']') {
                    return Ok(Value::Array(values));
                }
                loop {
                    if values.len() >= 64 {
                        return Err(Error);
                    }
                    values.push(self.value(depth + 1)?);
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(Error);
                    }
                }
                Ok(Value::Array(values))
            }
            b'"' => self.string().map(Value::String),
            b'0'..=b'9' => {
                let start = self.index;
                let mut n = 0i64;
                while let Some(b @ b'0'..=b'9') = self.bytes.get(self.index) {
                    n = n
                        .checked_mul(10)
                        .and_then(|n| n.checked_add(i64::from(b - b'0')))
                        .ok_or(Error)?;
                    self.index += 1;
                }
                if self.index - start > 1 && self.bytes[start] == b'0' {
                    return Err(Error);
                }
                Ok(Value::Integer(n))
            }
            _ => Err(Error),
        }
    }
}
