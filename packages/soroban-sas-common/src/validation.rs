use crate::errors::SASError;
use crate::RevocationPolicy;
use soroban_sdk::{Address, Bytes, Env, String};

const MAX_SCHEMA_LENGTH: u32 = 1024;
const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ZERO_CONTRACT_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn trim_bounds(bytes: &Bytes, mut start: u32, mut end: u32) -> Option<(u32, u32)> {
    while start < end {
        if !is_ascii_whitespace(bytes.get(start)?) {
            break;
        }
        start += 1;
    }

    while end > start {
        if !is_ascii_whitespace(bytes.get(end - 1)?) {
            break;
        }
        end -= 1;
    }

    if start >= end {
        None
    } else {
        Some((start, end))
    }
}

fn is_valid_identifier(bytes: &Bytes, start: u32, end: u32) -> bool {
    if start >= end {
        return false;
    }

    let Some(first) = bytes.get(start) else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }

    for index in (start + 1)..end {
        let Some(byte) = bytes.get(index) else {
            return false;
        };
        if !(byte.is_ascii_alphanumeric() || byte == b'_') {
            return false;
        }
    }

    true
}

fn is_valid_type(bytes: &Bytes, start: u32, end: u32) -> bool {
    if start >= end {
        return false;
    }

    let mut has_alpha = false;
    for index in start..end {
        let Some(byte) = bytes.get(index) else {
            return false;
        };
        if byte.is_ascii_alphabetic() {
            has_alpha = true;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'<' | b'>' | b'[' | b']' | b',' | b':' | b'(' | b')' | b' ' | b'?'
            ))
        {
            return false;
        }
    }

    has_alpha
}

pub fn validate_schema_syntax(env: &Env, schema: &String) -> Result<(), SASError> {
    let schema_len = schema.len() as usize;
    if schema_len == 0 || schema_len > MAX_SCHEMA_LENGTH as usize {
        return Err(SASError::InvalidSchema);
    }
    let mut buf = [0u8; 1024]; // Hardcoded to MAX_SCHEMA_LENGTH
    schema.copy_into_slice(&mut buf[..schema_len]);
    let schema_bytes = Bytes::from_slice(env, &buf[..schema_len]);

    let Some((mut start, end)) = trim_bounds(&schema_bytes, 0, schema_bytes.len()) else {
        return Err(SASError::InvalidSchema);
    };

    let mut field_count = 0u32;
    while start < end {
        let mut field_end = start;
        while field_end < end {
            let Some(byte) = schema_bytes.get(field_end) else {
                return Err(SASError::InvalidSchema);
            };
            if byte == b',' {
                break;
            }
            field_end += 1;
        }

        let Some((field_start, field_end)) = trim_bounds(&schema_bytes, start, field_end) else {
            return Err(SASError::InvalidSchema);
        };

        let mut split_index = field_start;
        while split_index < field_end {
            let Some(byte) = schema_bytes.get(split_index) else {
                return Err(SASError::InvalidSchema);
            };
            if is_ascii_whitespace(byte) {
                break;
            }
            split_index += 1;
        }

        if split_index == field_start || split_index >= field_end {
            return Err(SASError::InvalidSchema);
        }

        let mut ty_start = split_index;
        while ty_start < field_end {
            let Some(byte) = schema_bytes.get(ty_start) else {
                return Err(SASError::InvalidSchema);
            };
            if !is_ascii_whitespace(byte) {
                break;
            }
            ty_start += 1;
        }

        if ty_start >= field_end
            || !is_valid_identifier(&schema_bytes, field_start, split_index)
            || !is_valid_type(&schema_bytes, ty_start, field_end)
        {
            return Err(SASError::InvalidSchema);
        }
        field_count += 1;

        if field_end >= end {
            break;
        }
        start = field_end + 1;
        while start < end {
            let Some(byte) = schema_bytes.get(start) else {
                return Err(SASError::InvalidSchema);
            };
            if !is_ascii_whitespace(byte) {
                break;
            }
            start += 1;
        }
        if start >= end {
            return Err(SASError::InvalidSchema);
        }
    }

    if field_count == 0 {
        return Err(SASError::InvalidSchema);
    }

    Ok(())
}

pub fn validate_ttl(_env: &Env, current_time: u64, expiration_time: u64) -> Result<(), SASError> {
    if expiration_time > 0 && current_time >= expiration_time {
        return Err(SASError::InvalidTTL);
    }
    Ok(())
}

pub fn validate_recipient(_env: &Env, recipient: &Address) -> Result<(), SASError> {
    let zero_account = Address::from_string(&String::from_str(_env, ZERO_ACCOUNT_STRKEY));
    let zero_contract = Address::from_string(&String::from_str(_env, ZERO_CONTRACT_STRKEY));
    if recipient == &zero_account || recipient == &zero_contract {
        return Err(SASError::InvalidRecipient);
    }
    Ok(())
}

/// Validates an attestation's `revocable` flag against a schema's tri-state
/// [`RevocationPolicy`] (#448).
///
/// * `RevocableOnly` rejects an irrevocable attestation with
///   [`SASError::InvalidRevocability`].
/// * `IrrevocableOnly` rejects a revocable attestation with
///   [`SASError::NotRevocable`].
/// * `Permissive` accepts either flag.
pub fn check_policy(policy: RevocationPolicy, attestation_revocable: bool) -> Result<(), SASError> {
    match policy {
        RevocationPolicy::RevocableOnly => {
            if !attestation_revocable {
                return Err(SASError::InvalidRevocability);
            }
        }
        RevocationPolicy::IrrevocableOnly => {
            if attestation_revocable {
                return Err(SASError::NotRevocable);
            }
        }
        RevocationPolicy::Permissive => {}
    }
    Ok(())
}

pub fn check_revocable(
    _env: &Env,
    schema_revocable: bool,
    attestation_revocable: bool,
) -> Result<(), SASError> {
    check_policy(
        RevocationPolicy::from(schema_revocable),
        attestation_revocable,
    )
}

/// Returns `true` if `bytes` contain any byte or code point that is forbidden
/// in a schema definition string: an ASCII control character (`< 0x20`),
/// `DEL` (`0x7F`), invalid UTF-8, or a non-ASCII unicode whitespace / invisible
/// formatting code point (e.g. NBSP `U+00A0`, zero-width space `U+200B`, BOM
/// `U+FEFF`). These characters are invisible or render inconsistently across
/// SDK parsers and can drive hash divergence between otherwise-identical
/// schemas (#447).
fn contains_control_or_invalid_whitespace(bytes: &[u8]) -> bool {
    for &b in bytes {
        if b < 0x20 || b == 0x7F {
            return true;
        }
    }
    match core::str::from_utf8(bytes) {
        Ok(s) => {
            for c in s.chars() {
                if c == ' ' {
                    continue;
                }
                if c.is_whitespace() || c.is_control() {
                    return true;
                }
                if matches!(
                    c,
                    '\u{00A0}' | '\u{00AD}' | '\u{0085}' | '\u{1680}' | '\u{2000}'
                        ..='\u{200F}'
                            | '\u{2028}'
                            | '\u{2029}'
                            | '\u{202F}'
                            | '\u{205F}'
                            | '\u{2060}'
                            | '\u{3000}'
                            | '\u{FEFF}'
                ) {
                    return true;
                }
            }
            false
        }
        // Non-UTF-8 bytes are never a valid schema definition.
        Err(_) => true,
    }
}

/// Strict lexical validation of a schema definition string (#447).
///
/// Runs *before* [`validate_schema_syntax`] and rejects, with
/// [`SASError::InvalidSchemaDefinition`], any string that:
///
/// * contains control characters, `DEL`, invalid UTF-8, or invisible / unicode
///   whitespace (see [`contains_control_or_invalid_whitespace`]);
/// * has a leading or trailing field delimiter (`,`);
/// * uses non-canonical separators: two consecutive spaces anywhere, a space
///   immediately before a comma, or more than one space after a comma.
///
/// Whitespace-only or empty strings are intentionally *not* rejected here;
/// they fall through to [`validate_schema_syntax`], which reports them as
/// [`SASError::InvalidSchema`]. This keeps the lexical layer focused on
/// character-level hygiene and canonical spacing, while structural emptiness
/// stays a syntax concern.
pub fn validate_schema_lexical(_env: &Env, schema: &String) -> Result<(), SASError> {
    let schema_len = schema.len() as usize;
    if schema_len == 0 {
        // Deferred to the syntax validator, which maps this to InvalidSchema.
        return Ok(());
    }
    if schema_len > MAX_SCHEMA_LENGTH as usize {
        return Err(SASError::InvalidSchemaDefinition);
    }
    let mut buf = [0u8; MAX_SCHEMA_LENGTH as usize];
    schema.copy_into_slice(&mut buf[..schema_len]);
    let bytes = &buf[..schema_len];

    if contains_control_or_invalid_whitespace(bytes) {
        return Err(SASError::InvalidSchemaDefinition);
    }

    // Canonical separator rules. All bytes here are guaranteed ASCII by the
    // control/whitespace check above.
    let mut index = 0usize;
    while index < schema_len {
        let byte = bytes[index];
        if byte == b' ' {
            // Two consecutive spaces are never canonical.
            if index + 1 < schema_len && bytes[index + 1] == b' ' {
                return Err(SASError::InvalidSchemaDefinition);
            }
            // A space immediately before a comma is a malformed separator.
            if index + 1 < schema_len && bytes[index + 1] == b',' {
                return Err(SASError::InvalidSchemaDefinition);
            }
        } else if byte == b',' {
            // Trailing comma, or two commas with nothing (or only a space)
            // between them, is malformed.
            if index + 1 >= schema_len {
                return Err(SASError::InvalidSchemaDefinition);
            }
            if bytes[index + 1] == b',' {
                return Err(SASError::InvalidSchemaDefinition);
            }
            // At most one space may follow a comma.
            if bytes[index + 1] == b' ' && index + 2 < schema_len && bytes[index + 2] == b' ' {
                return Err(SASError::InvalidSchemaDefinition);
            }
        }
        index += 1;
    }

    // Leading delimiter (ignoring a single canonical leading space is still a
    // malformed schema, but that is left to the syntax validator; a leading
    // comma, however, is unambiguously malformed).
    if bytes[0] == b',' {
        return Err(SASError::InvalidSchemaDefinition);
    }

    Ok(())
}
