use libsm::{sm3, sm4};

/// encrypt plaintext with password
pub fn sm4_encrypt(plaintext: &[u8], password: &str) -> Vec<u8> {
    let pwd_hash = sm3::hash::Sm3Hash::new(password.as_bytes()).get_hash();

    let (key, iv) = pwd_hash.split_at(16);
    let cipher = sm4::Cipher::new(key, sm4::Mode::Cbc);

    cipher.encrypt(plaintext, iv)
}

/// decrypt plaintext with password
pub fn sm4_decrypt(ciphertext: &[u8], password: &str) -> Vec<u8> {
    let pwd_hash = sm3::hash::Sm3Hash::new(password.as_bytes()).get_hash();

    let (key, iv) = pwd_hash.split_at(16);
    let cipher = sm4::Cipher::new(key, sm4::Mode::Cbc);

    cipher.decrypt(ciphertext, iv)
}
