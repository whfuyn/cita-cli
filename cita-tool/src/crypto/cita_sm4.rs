use libsm::sm4;

/// encrypt plaintext with key and iv
pub fn sm4_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = sm4::Cipher::new(key, sm4::Mode::Cbc);
    cipher.encrypt(plaintext, iv)
}

/// decrypt ciphertext with key and iv
pub fn sm4_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = sm4::Cipher::new(key, sm4::Mode::Cbc);
    cipher.decrypt(ciphertext, iv)
}
