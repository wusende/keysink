use crate::error::{Error, Result};
use crate::util;
use rand::RngCore;
use std::io::{IsTerminal, Read};

const LOG_N: u8 = 15;
const R: u32 = 8;
const P: u32 = 1;
const OUT_LEN: usize = 32;

/// Generate a storable password verification string: `scrypt$<log_n>$<r>$<p>$<salt_hex>$<hash_hex>`.
pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err(Error::msg("master password 不能为空"));
    }
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let params = scrypt::Params::new(LOG_N, R, P, OUT_LEN)
        .map_err(|e| Error::msg(format!("scrypt 参数非法: {e}")))?;
    let mut out = [0u8; OUT_LEN];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::msg(format!("scrypt 计算失败: {e}")))?;
    Ok(format!(
        "scrypt${LOG_N}${R}${P}${}${}",
        util::hex(&salt),
        util::hex(&out)
    ))
}

/// Verify a password; `encoded` is the output of `hash_password`.
pub fn verify_password(password: &str, encoded: &str) -> Result<bool> {
    let mut parts = encoded.split('$');
    if parts.next() != Some("scrypt") {
        return Err(Error::msg("密码校验串格式非法"));
    }
    let log_n: u8 = parse(parts.next(), "log_n")?;
    let r: u32 = parse(parts.next(), "r")?;
    let p: u32 = parse(parts.next(), "p")?;
    let salt = hex_decode(parts.next().ok_or_else(|| Error::msg("缺少 salt"))?)?;
    let expected = hex_decode(parts.next().ok_or_else(|| Error::msg("缺少 hash"))?)?;
    let params = scrypt::Params::new(log_n, r, p, expected.len())
        .map_err(|e| Error::msg(format!("scrypt 参数非法: {e}")))?;
    let mut out = vec![0u8; expected.len()];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut out)
        .map_err(|e| Error::msg(format!("scrypt 计算失败: {e}")))?;
    Ok(constant_time_eq(&out, &expected))
}

fn parse<T: std::str::FromStr>(value: Option<&str>, what: &str) -> Result<T> {
    value
        .ok_or_else(|| Error::msg(format!("密码校验串缺少 {what}")))?
        .parse()
        .map_err(|_| Error::msg(format!("密码校验串 {what} 非法")))
}

fn hex_decode(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::msg("密码校验串 hex 长度非法"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error::msg("密码校验串 hex 非法"))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error::msg("密码校验串 hex 非法"))?;
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

/// Set the password during init: hidden input entered twice on a TTY; with `--password-stdin` read one line.
pub fn read_new_password(from_stdin: bool) -> Result<String> {
    let password = if from_stdin {
        read_line()?
    } else if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("设置 master password: ")?;
        let second = rpassword::prompt_password("再输一次: ")?;
        if first != second {
            return Err(Error::msg("两次输入的密码不一致"));
        }
        first
    } else {
        return Err(Error::msg(
            "非交互环境初始化请加 --password-stdin（从 stdin 读一行）",
        ));
    };
    if password.is_empty() {
        return Err(Error::msg("master password 不能为空"));
    }
    Ok(password)
}

/// Verify the password before export: hidden input on a TTY; with `--password-stdin` read one line.
pub fn read_existing_password(from_stdin: bool) -> Result<String> {
    if from_stdin {
        read_line()
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("master password: ").map_err(Error::from)
    } else {
        Err(Error::msg(
            "非交互环境读取请加 --password-stdin（从 stdin 读一行）",
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
}
