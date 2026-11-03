use crate::error::{Error, Result};
use crate::util;
use rand::Rng;
use std::io::{IsTerminal, Read};

const LOG_N: u8 = 15;
const R: u32 = 8;
const P: u32 = 1;
const OUT_LEN: usize = 32;

/// Generate a storable password verification string: `scrypt$<log_n>$<r>$<p>$<salt_hex>$<hash_hex>`.
pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err(Error::msg("master password must not be empty"));
    }
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let params = scrypt::Params::new(LOG_N, R, P)
        .map_err(|e| Error::msg(format!("invalid scrypt parameters: {e}")))?;
    let mut out = [0u8; OUT_LEN];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::msg(format!("scrypt computation failed: {e}")))?;
    Ok(format!(
        "scrypt${LOG_N}${R}${P}${}${}",
        util::hex(&salt),
        util::hex(&out)
    ))
}

/// `encoded` is a hash_password() output ("scrypt$log_n$r$p$salt$hash");
/// anything else is rejected as malformed rather than failing to match.
pub fn verify_password(password: &str, encoded: &str) -> Result<bool> {
    let mut parts = encoded.split('$');
    if parts.next() != Some("scrypt") {
        return Err(Error::msg("malformed password verification string"));
    }
    let log_n: u8 = parse(parts.next(), "log_n")?;
    let r: u32 = parse(parts.next(), "r")?;
    let p: u32 = parse(parts.next(), "p")?;
    let salt = hex_decode(parts.next().ok_or_else(|| Error::msg("missing salt"))?)?;
    let expected = hex_decode(parts.next().ok_or_else(|| Error::msg("missing hash"))?)?;
    // scrypt's own Params::new only rejects log_n >= 64 (overflow), so a
    // tampered password_hash string could otherwise push scrypt() into a
    // multi-GB state allocation and abort the process. Legit hashes are
    // minted by hash_password at log_n=15/r=8 (~32 MiB); cap at 256 MiB.
    let state_mem = (1u64 << log_n.min(62))
        .checked_mul(r as u64)
        .and_then(|v| v.checked_mul(128));
    match state_mem {
        Some(mem) if mem <= 256 * 1024 * 1024 => {}
        _ => return Err(Error::msg("password hash scrypt params too large")),
    }
    let params = scrypt::Params::new(log_n, r, p)
        .map_err(|e| Error::msg(format!("invalid scrypt parameters: {e}")))?;
    let mut out = vec![0u8; expected.len()];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::msg(format!("scrypt computation failed: {e}")))?;
    Ok(constant_time_eq(&out, &expected))
}

fn parse<T: std::str::FromStr>(value: Option<&str>, what: &str) -> Result<T> {
    value
        .ok_or_else(|| Error::msg(format!("password verification string missing {what}")))?
        .parse()
        .map_err(|_| Error::msg(format!("invalid {what} in password verification string")))
}

fn hex_decode(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::msg(
            "invalid hex length in password verification string",
        ));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error::msg("invalid hex in password verification string"))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error::msg("invalid hex in password verification string"))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn read_new_password(from_stdin: bool) -> Result<String> {
    let password = if from_stdin {
        read_line()?
    } else if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("Set master password: ")?;
        let second = rpassword::prompt_password("Enter again: ")?;
        if first != second {
            return Err(Error::msg("passwords do not match"));
        }
        first
    } else {
        return Err(Error::msg(
            "non-interactive init requires --password-stdin (reads one line from stdin)",
        ));
    };
    if password.is_empty() {
        return Err(Error::msg("master password must not be empty"));
    }
    Ok(password)
}

pub fn read_existing_password(from_stdin: bool) -> Result<String> {
    if from_stdin {
        read_line()
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("master password: ").map_err(Error::from)
    } else {
        Err(Error::msg(
            "non-interactive read requires --password-stdin (reads one line from stdin)",
        ))
    }
}

fn read_line() -> Result<String> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let encoded = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &encoded).unwrap());
        assert!(!verify_password("wrong", &encoded).unwrap());
    }

    #[test]
    fn rejects_empty_password() {
        assert!(hash_password("").is_err());
    }

    #[test]
    fn rejects_oversized_scrypt_params_before_allocating() {
        // Without the memory guard, scrypt::Params::new happily accepts
        // log_n=40 / r=2^28 and scrypt() then aborts the process trying to
        // touch tens of GB of state.
        let huge_log_n =
            "scrypt$40$8$1$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff";
        assert!(verify_password("x", huge_log_n).is_err());

        let huge_r = "scrypt$15$268435456$1$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff";
        assert!(verify_password("x", huge_r).is_err());
    }
}
