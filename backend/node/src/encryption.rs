use aes_gcm::aead::{ generic_array::GenericArray, Aead, NewAead };
use aes_gcm::Aes256Gcm;
use anyhow::{ anyhow, bail, Context, Result };
use curv::elliptic::curves::{ Curve, Point, Scalar };
use curv::{ arithmetic::traits::Converter, BigInt };
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ Digest, PublicKey, SecretKey, Sha512 };
use nkeys::{ KeyPair, KeyPairType };
use serde::de::DeserializeOwned;
use serde::Serialize;
use shared::recovery::EncryptedData;
use std::fmt::Debug;
use std::iter::Iterator;

pub const AES_KEY_BYTES_LEN: usize = 32;

macro_rules! length_mismatch {
    () => {
        "The key provided has length {}, rather than the reqired length of {}"
    };
}

pub fn serialize_and_encrypt<T: Serialize>(
    input: &T,
    encryption_key: &[u8]
) -> Result<EncryptedData> {
    let s = serde_json::to_vec(&input)?;

    aes_encrypt(&s, encryption_key)
}

pub fn decrypt_and_deserialize<T: DeserializeOwned>(
    input: &EncryptedData,
    decryption_key: &[u8]
) -> Result<T> {
    let dc = aes_decrypt(input, decryption_key)?;
    let ds = serde_json::from_slice::<T>(&dc)?;
    Ok(ds)
}

pub fn aes_encrypt(plaintext: &[u8], encryption_key: &[u8]) -> Result<EncryptedData> {
    // create aes-gcm for sending encrypted message
    if encryption_key.len() != AES_KEY_BYTES_LEN {
        return Err(anyhow!(length_mismatch!(), encryption_key.len(), AES_KEY_BYTES_LEN));
    }
    let key = GenericArray::from_slice(&encryption_key);
    //TODO: improve nonce
    let nonce_bytes = &mut get_secure_random_bits(96);
    let nonce = GenericArray::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(&key);

    let aead_pack_i_ne = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow!("{}", "Encryption algorithm failed with an opaque error"))?;
    let send_nonce = nonce_bytes.clone();
    Ok(EncryptedData {
        aead_pack: aead_pack_i_ne,
        nonce: send_nonce,
    })
}

pub fn aes_decrypt(encrypted_data: &EncryptedData, encryption_key: &[u8]) -> Result<Vec<u8>> {
    if encryption_key.len() != AES_KEY_BYTES_LEN {
        bail!(length_mismatch!(), encryption_key.len(), AES_KEY_BYTES_LEN);
    }
    let key = GenericArray::from_slice(&encryption_key);
    let nonce = GenericArray::from_slice(&encrypted_data.nonce);
    let cipher = Aes256Gcm::new(&key);

    let result = cipher
        .decrypt(nonce, encrypted_data.aead_pack.as_ref())
        .map_err(|_| anyhow!("{}", "Decryption algorithm failed with an opaque error"))?;
    Ok(result)
}

pub fn encryption_key_for_aes<C>(
    other_public: &Point<C>,
    local_secret: &Scalar<C>
) -> Result<Vec<u8>>
    where C: Curve
{
    let point: Point<C> = other_public.clone() * local_secret.clone();
    let x_coord = point.x_coord().unwrap();
    let key_bytes: Vec<u8> = BigInt::to_bytes(&x_coord);
    match AES_KEY_BYTES_LEN - key_bytes.len() {
        x if x == 0 => Ok(key_bytes),
        x if x > 0 => {
            let mut encryption_key: Vec<u8> = vec![0u8; x];
            encryption_key.extend_from_slice(&key_bytes[..]);
            Ok(encryption_key)
        }
        _ => {
            bail!("encryption key length is too long");
        }
    }
}

pub fn shared_secrets_from_nkeys(
    private_key: &str,
    public_keys: &Vec<String>
) -> Result<Vec<Vec<u8>>> {
    let sk = private_key_from_seed(private_key)?;
    public_keys
        .iter()
        .map(|x| shared_secret_from_nkey_sk(&sk, x))
        .collect()
}

pub fn shared_secret_from_nkeys(private_key: &str, public_key: &str) -> Result<Vec<u8>> {
    let sk = private_key_from_seed(private_key)?;
    let public_kp: KeyPairExposed = KeyPair::from_public_key(public_key)?.into();

    create_shared_secret(&sk, &public_kp.pk)
}

fn private_key_from_seed(private_key: &str) -> Result<SecretKey> {
    let private_kp: KeyPairExposed = KeyPair::from_seed(private_key)?.into();
    let sk = private_kp.sk.context("Invalid seed phrase for private key")?;
    Ok(sk)
}

fn shared_secret_from_nkey_sk(private_key: &SecretKey, public_key: &str) -> Result<Vec<u8>> {
    let public_kp: KeyPairExposed = KeyPair::from_public_key(public_key)?.into();

    create_shared_secret(&private_key, &public_kp.pk)
}

pub fn encrypt_with_shared_secret(
    plaintext: &[u8],
    private_key: &str,
    public_key: &str
) -> Result<EncryptedData> {
    let private_kp: KeyPairExposed = KeyPair::from_seed(private_key)?.into();
    let public_kp: KeyPairExposed = KeyPair::from_public_key(public_key)?.into();

    let shared_secret = create_shared_secret(&private_kp.sk.unwrap(), &public_kp.pk)?;
    let encrypted = aes_encrypt(plaintext, &shared_secret)?;
    Ok(encrypted)
}

#[allow(dead_code)]
pub fn decrypt_with_shared_secret(
    encrypted: EncryptedData,
    private_key: &str,
    public_key: &str
) -> Result<Vec<u8>> {
    let private_kp: KeyPairExposed = KeyPair::from_seed(private_key)?.into();
    let public_kp: KeyPairExposed = KeyPair::from_public_key(public_key)?.into();

    let shared_secret = create_shared_secret(&private_kp.sk.unwrap(), &public_kp.pk)?;
    let decrypted = aes_decrypt(&encrypted, &shared_secret)?;
    Ok(decrypted)
}

fn create_shared_secret(private_key: &SecretKey, public_key: &PublicKey) -> Result<Vec<u8>> {
    let compressed_y = CompressedEdwardsY::from_slice(&public_key.to_bytes()[..]);
    let pub_key_point = match compressed_y.decompress() {
        Some(p) => p,
        None => bail!("Invalid public key"),
    };

    let hash = Sha512::digest(&private_key.to_bytes()[..32]);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    let private_key_scalar = clamp_scalar(output);

    let ss = private_key_scalar * pub_key_point;
    Ok(ss.compress().to_bytes().to_vec())
}

//ensures key is on the main prime-order subgroup
//see https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/
fn clamp_scalar(mut scalar: [u8; 32]) -> curve25519_dalek::scalar::Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    curve25519_dalek::scalar::Scalar::from_bits(scalar)
}

#[derive(Debug)]
struct KeyPairExposed {
    pub kp_type: KeyPairType,
    pub sk: Option<SecretKey>,
    pub pk: PublicKey,
}

impl From<KeyPair> for KeyPairExposed {
    fn from(kp: KeyPair) -> Self {
        unsafe { std::mem::transmute::<KeyPair, Self>(kp) }
    }
}

/// Fills the provided buffer with secure random bytes.
pub fn fill_secure_random(buffer: &mut [u8]) {
    use rand::prelude::*;
    rand::thread_rng().fill_bytes(buffer);
}

/// Returns a vector filled with random bytes.
pub fn get_secure_random_bytes(bytes: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; bytes];
    fill_secure_random(&mut buffer);
    buffer
}

/// Returns a vector filled with random bits. The number of bytes returned is computed from the number of bits set.
pub fn get_secure_random_bits(bits: usize) -> Vec<u8> {
    get_secure_random_bytes(bits / 8_usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::elliptic::curves::Ed25519;

    #[test]
    fn can_aes_encry_decrypt_with_ed25519() {
        let ec_point = Point::<Ed25519>::generator();

        let s1 = Scalar::random();
        let p1 = ec_point.to_point() * &s1;

        let s2 = Scalar::random();
        let p2 = ec_point * &s2;

        let k1 = encryption_key_for_aes(&p2, &s1).unwrap();
        let k2 = encryption_key_for_aes(&p1, &s2).unwrap();

        assert_eq!(k1, k2);
    }

    #[test]
    fn can_generate_matching_shared_secrets() {
        // change these to ed25519 keys
        let kp1: KeyPairExposed = KeyPair::new_user().into();
        let kp2: KeyPairExposed = KeyPair::new_user().into();

        let ss1 = create_shared_secret(&kp1.sk.unwrap(), &kp2.pk).expect(
            "shared secret creation failed"
        );
        let ss2 = create_shared_secret(&kp2.sk.unwrap(), &kp1.pk).expect(
            "shared secret creation failed"
        );

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn can_decrypt_encrypted_data() {
        let plaintext = b"plaintext to be encrypted".to_vec();
        let key = vec![0u8; 32];

        let encrypted = aes_encrypt(&plaintext, &key).expect("encryption failed");
        let decrypted = aes_decrypt(&encrypted, &key).expect("decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn can_decrypt_data_encrypted_with_shared_secret() {
        let kp1 = KeyPair::new_user();
        let kp2 = KeyPair::new_user();

        let seed1 = kp1.seed().unwrap();
        let seed2 = kp2.seed().unwrap();
        let public_key1 = kp1.public_key();
        let public_key2 = kp2.public_key();

        let plaintext = b"plaintext to be encrypted".to_vec();

        let encrypted = encrypt_with_shared_secret(&plaintext, &seed1, &public_key2).unwrap();
        let decrypted = decrypt_with_shared_secret(encrypted, &seed2, &public_key1).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
