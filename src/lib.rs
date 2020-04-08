mod utils;

use wasm_bindgen::prelude::*;

use ursa::{
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
    seed: Vec<u8>,
    scheme: secp256k1::EcdsaSecp256k1Sha256,
}

#[wasm_bindgen]
impl VKP {
    pub fn new(seed: Vec<u8>) -> VKP {
        VKP {
            seed: seed,
            scheme: secp256k1::EcdsaSecp256k1Sha256::new(),
        }
    }
    pub fn get_public_key(&self, deriv_path: &str) -> Vec<u8> {
        let dk = ExtendedPrivKey::derive(&self.seed, deriv_path).unwrap();
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
    pub fn sign(&self, deriv_path: &str, digest: Vec<u8>) -> Vec<u8> {
        let dk = ExtendedPrivKey::derive(&self.seed, deriv_path).unwrap();
        let kp = self
            .scheme
            .keypair(Some(KeyGenOption::FromSecretKey(PrivateKey(
                dk.secret().to_vec(),
            ))))
            .unwrap();

        return self.scheme.sign(&digest, &kp.1).unwrap();
    }
}
