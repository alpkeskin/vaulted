//! Minimal lowercase hex codec, used for blind index serialization.
//!
//! Hand-rolled rather than pulled in as a dependency: it is twenty lines, and
//! every dependency in a security-critical crate has to earn its place.

use crate::error::BlindIndexError;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encodes bytes as lowercase hex.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes lowercase or uppercase hex. Rejects odd lengths and non-hex bytes.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, BlindIndexError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return Err(BlindIndexError::Malformed);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(byte: u8) -> Result<u8, BlindIndexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BlindIndexError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(decode("000fff").unwrap(), vec![0x00, 0x0f, 0xff]);
        assert_eq!(decode("000FFF").unwrap(), vec![0x00, 0x0f, 0xff]);
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in ["", "abc", "zz", "0g", "00 ", "00\n"] {
            assert!(decode(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
