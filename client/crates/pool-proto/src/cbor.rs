//! Deterministic CBOR (RFC 8949 section 4.2.1, "core deterministic encoding") on top of `ciborium::Value`.
//!
//! ciborium already writes shortest-form integers and definite lengths. What it does not do is sort map
//! keys, so [`canonicalize`] sorts every map bytewise by the encoded key. [`decode_deterministic`] rejects
//! duplicate keys and any input that does not re-encode to the identical bytes.

use ciborium::value::Integer;
pub use ciborium::value::Value;

use crate::Error;

/// Encode a value (any nesting) deterministically.
pub fn encode(value: &Value) -> Vec<u8> {
    let canon = canonicalize(value);
    let mut out = Vec::new();
    ciborium::into_writer(&canon, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

fn encode_raw(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

/// Return a copy with all maps sorted bytewise by encoded key.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Map(entries) => {
            let mut sorted: Vec<(Vec<u8>, Value, Value)> = entries
                .iter()
                .map(|(k, v)| {
                    let k = canonicalize(k);
                    (encode_raw(&k), k, canonicalize(v))
                })
                .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Map(sorted.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Tag(t, inner) => Value::Tag(*t, Box::new(canonicalize(inner))),
        other => other.clone(),
    }
}

fn has_duplicate_keys(value: &Value) -> bool {
    match value {
        Value::Map(entries) => {
            let mut keys: Vec<Vec<u8>> = entries.iter().map(|(k, _)| encode_raw(k)).collect();
            let n = keys.len();
            keys.sort();
            keys.dedup();
            keys.len() != n || entries.iter().any(|(k, v)| has_duplicate_keys(k) || has_duplicate_keys(v))
        }
        Value::Array(items) => items.iter().any(has_duplicate_keys),
        Value::Tag(_, inner) => has_duplicate_keys(inner),
        _ => false,
    }
}

/// Decode bytes that must be exactly one deterministically encoded CBOR item.
pub fn decode_deterministic(bytes: &[u8]) -> Result<Value, Error> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| Error::Malformed("not CBOR"))?;
    if has_duplicate_keys(&value) {
        return Err(Error::Malformed("duplicate map keys"));
    }
    if encode(&value) != bytes {
        return Err(Error::Malformed("non-deterministic CBOR encoding"));
    }
    Ok(value)
}

/// Decode one CBOR item without the determinism check (used for the COSE envelope itself, whose
/// signed parts are checked separately).
pub fn decode_any(bytes: &[u8]) -> Result<Value, Error> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| Error::Malformed("not CBOR"))?;
    if encode_raw(&value).len() != bytes.len() {
        return Err(Error::Malformed("trailing bytes after CBOR item"));
    }
    Ok(value)
}

// ------------------------------------------------------------------ building and reading claim maps

/// Builder for text-keyed claim maps.
#[derive(Default)]
pub struct MapBuilder(Vec<(Value, Value)>);

impl MapBuilder {
    pub fn new(type_str: &str) -> Self {
        Self::default().text("type", type_str)
    }
    pub fn text(mut self, k: &str, v: &str) -> Self {
        self.0.push((Value::Text(k.into()), Value::Text(v.into())));
        self
    }
    pub fn bytes(mut self, k: &str, v: &[u8]) -> Self {
        self.0.push((Value::Text(k.into()), Value::Bytes(v.to_vec())));
        self
    }
    pub fn uint(mut self, k: &str, v: u64) -> Self {
        self.0.push((Value::Text(k.into()), Value::Integer(Integer::from(v))));
        self
    }
    pub fn int(mut self, k: &str, v: i64) -> Self {
        self.0.push((Value::Text(k.into()), Value::Integer(Integer::from(v))));
        self
    }
    pub fn value(mut self, k: &str, v: Value) -> Self {
        self.0.push((Value::Text(k.into()), v));
        self
    }
    pub fn opt_uint(self, k: &str, v: Option<u64>) -> Self {
        match v {
            Some(v) => self.uint(k, v),
            None => self,
        }
    }
    pub fn opt_text(self, k: &str, v: Option<&str>) -> Self {
        match v {
            Some(v) => self.text(k, v),
            None => self,
        }
    }
    pub fn opt_bytes(self, k: &str, v: Option<&[u8]>) -> Self {
        match v {
            Some(v) => self.bytes(k, v),
            None => self,
        }
    }
    pub fn build(self) -> Value {
        Value::Map(self.0)
    }
}

/// Reader for closed, text-keyed claim maps: unknown keys are rejected.
pub struct MapReader<'a> {
    entries: &'a [(Value, Value)],
}

impl<'a> MapReader<'a> {
    /// `required` and `optional` together are the full allowed key set (closed map).
    pub fn new(value: &'a Value, required: &[&str], optional: &[&str]) -> Result<Self, Error> {
        let Value::Map(entries) = value else {
            return Err(Error::Malformed("claims must be a map"));
        };
        for (k, _) in entries {
            let Value::Text(k) = k else {
                return Err(Error::Malformed("non-text map key"));
            };
            if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
                return Err(Error::Malformed("unknown key in closed map"));
            }
        }
        let r = Self { entries };
        for k in required {
            if r.get(k).is_none() {
                return Err(Error::Malformed("missing required key"));
            }
        }
        Ok(r)
    }

    pub fn get(&self, key: &str) -> Option<&'a Value> {
        self.entries.iter().find_map(|(k, v)| match k {
            Value::Text(t) if t == key => Some(v),
            _ => None,
        })
    }

    fn req(&self, key: &str) -> Result<&'a Value, Error> {
        self.get(key).ok_or(Error::Malformed("missing required key"))
    }

    pub fn text(&self, key: &str) -> Result<String, Error> {
        match self.req(key)? {
            Value::Text(t) => Ok(t.clone()),
            _ => Err(Error::Malformed("expected text")),
        }
    }
    pub fn opt_text(&self, key: &str) -> Result<Option<String>, Error> {
        self.get(key).map(|_| self.text(key)).transpose()
    }
    pub fn bytes(&self, key: &str) -> Result<Vec<u8>, Error> {
        match self.req(key)? {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(Error::Malformed("expected bytes")),
        }
    }
    pub fn bytes_n<const N: usize>(&self, key: &str) -> Result<[u8; N], Error> {
        let b = self.bytes(key)?;
        b.try_into().map_err(|_| Error::Malformed("wrong byte string length"))
    }
    pub fn opt_bytes_n<const N: usize>(&self, key: &str) -> Result<Option<[u8; N]>, Error> {
        self.get(key).map(|_| self.bytes_n::<N>(key)).transpose()
    }
    pub fn uint(&self, key: &str) -> Result<u64, Error> {
        as_uint(self.req(key)?)
    }
    pub fn opt_uint(&self, key: &str) -> Result<Option<u64>, Error> {
        self.get(key).map(as_uint).transpose()
    }
    pub fn int(&self, key: &str) -> Result<i64, Error> {
        match self.req(key)? {
            Value::Integer(i) => i64::try_from(*i).map_err(|_| Error::Malformed("integer out of range")),
            _ => Err(Error::Malformed("expected integer")),
        }
    }
    pub fn array(&self, key: &str) -> Result<&'a [Value], Error> {
        match self.req(key)? {
            Value::Array(a) => Ok(a),
            _ => Err(Error::Malformed("expected array")),
        }
    }
    pub fn map(&self, key: &str) -> Result<&'a Value, Error> {
        match self.req(key)? {
            v @ Value::Map(_) => Ok(v),
            _ => Err(Error::Malformed("expected map")),
        }
    }
    pub fn expect_type(&self, type_str: &str) -> Result<(), Error> {
        if self.text("type")? == type_str {
            Ok(())
        } else {
            Err(Error::WrongType)
        }
    }
}

pub fn as_uint(v: &Value) -> Result<u64, Error> {
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| Error::Malformed("expected unsigned integer")),
        _ => Err(Error::Malformed("expected unsigned integer")),
    }
}

pub fn as_text(v: &Value) -> Result<String, Error> {
    match v {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(Error::Malformed("expected text")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_keys_sorted_bytewise_length_first() {
        let v = MapBuilder::default()
            .uint("zz", 1)
            .uint("a", 2)
            .uint("type", 3)
            .uint("b", 4)
            .build();
        let enc = encode(&v);
        let dec = decode_deterministic(&enc).unwrap();
        let Value::Map(m) = dec else { panic!() };
        let keys: Vec<_> = m.iter().map(|(k, _)| as_text(k).unwrap()).collect();
        assert_eq!(keys, vec!["a", "b", "zz", "type"]);
    }

    #[test]
    fn shortest_form_integers() {
        assert_eq!(encode(&Value::Integer(23u64.into())), vec![0x17]);
        assert_eq!(encode(&Value::Integer(24u64.into())), vec![0x18, 24]);
        assert_eq!(encode(&Value::Integer(1000u64.into())), vec![0x19, 0x03, 0xe8]);
    }

    #[test]
    fn rejects_non_deterministic_and_duplicates() {
        // {"b":1,"a":2} unsorted
        let unsorted = vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert!(decode_deterministic(&unsorted).is_err());
        // non-shortest integer 0x18 0x01
        assert!(decode_deterministic(&[0x18, 0x01]).is_err());
        // duplicate keys {"a":1,"a":2}
        let dup = vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        assert!(decode_deterministic(&dup).is_err());
        // indefinite-length array
        assert!(decode_deterministic(&[0x9f, 0x01, 0xff]).is_err());
        // trailing garbage
        assert!(decode_deterministic(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn closed_map_rejects_unknown_keys() {
        let v = MapBuilder::new("t").uint("x", 1).uint("evil", 2).build();
        assert!(MapReader::new(&v, &["type", "x"], &[]).is_err());
        assert!(MapReader::new(&v, &["type", "x"], &["evil"]).is_ok());
        assert!(MapReader::new(&v, &["type", "x", "y"], &["evil"]).is_err());
    }
}
