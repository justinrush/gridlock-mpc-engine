use anyhow::Result;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{
    gen_nonce,
    Nonce,
    PublicKey,
    SecretKey,
};

pub fn e2e_decrypt(
    encrypted_data: &str,
    e2e_private_key: &str,
    e2e_sender_public: &str
) -> Result<Vec<u8>> {
    let encrypted_data = base64::decode(encrypted_data)?;
    let e2e_local_private = base64::decode(e2e_private_key)?;
    let e2e_sender_public = base64::decode(e2e_sender_public)?;

    let nonce_size = box_::curve25519xsalsa20poly1305::NONCEBYTES;
    let nonce = Nonce::from_slice(&encrypted_data[..nonce_size]).ok_or_else(||
        anyhow::anyhow!("Invalid nonce")
    )?;
    let ciphertext = &encrypted_data[nonce_size..];

    let e2e_local_private = SecretKey::from_slice(&e2e_local_private).ok_or_else(||
        anyhow::anyhow!("Invalid private key")
    )?;
    let e2e_sender_public = PublicKey::from_slice(&e2e_sender_public).ok_or_else(||
        anyhow::anyhow!("Invalid public key")
    )?;
    let decrypted_data = box_
        ::open(ciphertext, &nonce, &e2e_sender_public, &e2e_local_private)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
    Ok(decrypted_data)
}

pub fn e2e_encrypt(message: &[u8], target_public: &str, local_private: &str) -> Result<String> {
    let target_public = base64::decode(target_public)?;
    let local_private = base64::decode(local_private)?;

    let target_public = box_::curve25519xsalsa20poly1305::PublicKey
        ::from_slice(&target_public)
        .ok_or_else(|| anyhow::anyhow!("Invalid target public key"))?;
    let local_private = box_::curve25519xsalsa20poly1305::SecretKey
        ::from_slice(&local_private)
        .ok_or_else(|| anyhow::anyhow!("Invalid local private key"))?;

    let nonce = gen_nonce();
    let ciphertext = box_::seal(message, &nonce, &target_public, &local_private);

    let mut encrypted_msg = nonce.0.to_vec();
    encrypted_msg.extend(ciphertext);

    Ok(base64::encode(&encrypted_msg))
}
