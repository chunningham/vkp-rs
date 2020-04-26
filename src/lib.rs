mod utils;

use wasm_bindgen::prelude::*;

use ursa::{
    encryption::symm::{aescbc::Aes256CbcHmac512, SymmetricEncryptor},
    keys::{KeyGenOption, PrivateKey, PublicKey},
    signatures::{secp256k1, SignatureScheme},
};

use tiny_hderive::bip32::ExtendedPrivKey;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, vkp-rs!");
}

#[wasm_bindgen]
pub struct VKP {
    encrypted_seed: Vec<u8>,
    scheme: secp256k1::EcdsaSecp256k1Sha256,
}

#[wasm_bindgen]
impl VKP {
    pub fn new(encrypted_seed: Vec<u8>) -> Self {
        VKP {
            encrypted_seed: encrypted_seed,
            scheme: secp256k1::EcdsaSecp256k1Sha256::new(),
        }
    }
    pub fn from_seed(seed: Vec<u8>, pass: &str) -> Self {
        let encryptor = SymmetricEncryptor::<Aes256CbcHmac512>::new_with_key(pass).unwrap();
        return Self::new(encryptor.encrypt_easy(&[].to_vec(), &seed).unwrap());
    }
    pub fn get_public_key(&self, deriv_path: &str, pass: &str) -> Vec<u8> {
        let dk = ExtendedPrivKey::derive(&self.decrypt_seed(pass), deriv_path).unwrap();
        let pk = self
            .scheme
            .keypair(Some(KeyGenOption::FromSecretKey(PrivateKey(
                dk.secret().to_vec(),
            ))))
            .unwrap()
            .0;
        return pk.0.clone();
    }
    pub fn verify(digest: Vec<u8>, signature: Vec<u8>, pub_key: Vec<u8>) -> bool {
        let scp = secp256k1::EcdsaSecp256k1Sha256::new();
        return scp
            .verify(&digest, &signature, &PublicKey(pub_key))
            .unwrap();
    }
    pub fn sign(&self, deriv_path: &str, pass: &str, digest: Vec<u8>) -> Vec<u8> {
        let dk = ExtendedPrivKey::derive(&self.decrypt_seed(pass), deriv_path).unwrap();
        let kp = self
            .scheme
            .keypair(Some(KeyGenOption::FromSecretKey(PrivateKey(
                dk.secret().to_vec(),
            ))))
            .unwrap();

        return self.scheme.sign(&digest, &kp.1).unwrap();
    }

    fn decrypt_seed(&self, pass: &str) -> Vec<u8> {
        let decryptor = SymmetricEncryptor::<Aes256CbcHmac512>::new_with_key(pass).unwrap();
        return decryptor
            .decrypt_easy(&[].to_vec(), &self.encrypted_seed)
            .unwrap();
    }
}
