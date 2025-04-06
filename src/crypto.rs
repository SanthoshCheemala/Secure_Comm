use rand::Rng;
use std::error::Error;

const PRIME: u64 = 23;
const GENERATOR: u64 = 5;

fn mod_pow(base: u64, exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exponent;
    
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    
    result
}

pub struct DiffieHellman {
    private_key: u64,
    public_key: u64,
    shared_secret: Option<u64>,
}

impl DiffieHellman {
    pub fn new() -> Self {
        let private_key = rand::thread_rng().gen_range(2..PRIME-1);
        let public_key = mod_pow(GENERATOR, private_key, PRIME);
        
        DiffieHellman {
            private_key,
            public_key,
            shared_secret: None,
        }
    }
    
    pub fn get_public_key(&self) -> u64 {
        self.public_key
    }
    
    pub fn compute_shared_secret(&mut self, other_public_key: u64) -> u64 {
        let secret = mod_pow(other_public_key, self.private_key, PRIME);
        self.shared_secret = Some(secret);
        secret
    }
    
    #[allow(dead_code)]
    pub fn get_shared_secret(&self) -> Option<u64> {
        self.shared_secret
    }
    
    pub fn derive_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match self.shared_secret {
            Some(secret) => {
                let mut key = Vec::new();
                let mut value = secret;
                
                for _ in 0..16 {
                    key.push((value & 0xFF) as u8);
                    value = value.rotate_right(8);
                }
                
                Ok(key)
            }
            None => Err("Shared secret not computed yet".into()),
        }
    }
}

pub struct XorCipher {
    pub key: Vec<u8>,
}

impl XorCipher {
    pub fn new(key: Vec<u8>) -> Self {
        XorCipher { key }
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ self.key[i % self.key.len()])
            .collect()
    }
    
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }
}

#[allow(dead_code)]
pub struct CaesarCipher {
    shift: u8,
}

#[allow(dead_code)]
impl CaesarCipher {
    pub fn new(key: &[u8]) -> Self {
        let shift = key.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
        CaesarCipher { shift }
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&byte| byte.wrapping_add(self.shift))
            .collect()
    }
    
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&byte| byte.wrapping_sub(self.shift))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diffie_hellman() {
        let mut alice = DiffieHellman::new();
        let mut bob = DiffieHellman::new();
        
        let alice_secret = alice.compute_shared_secret(bob.get_public_key());
        let bob_secret = bob.compute_shared_secret(alice.get_public_key());
        
        assert_eq!(alice_secret, bob_secret);
    }
    
    #[test]
    fn test_xor_cipher() {
        let key = vec![0x01, 0x02, 0x03, 0x04];
        let cipher = XorCipher::new(key);
        
        let plaintext = b"Hello, world!";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext);
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_caesar_cipher() {
        let key = vec![0x10, 0x20, 0x30];
        let cipher = CaesarCipher::new(&key);
        
        let plaintext = b"Hello, world!";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext);
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}
