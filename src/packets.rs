use cryptography::Nonce;
use cryptography::symmetric::Symmetric256Crypto;
use serde::{Deserialize, Serialize};

use bincode;

pub trait Serializable: Serialize + for<'de> Deserialize<'de> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error>
        where
            Self: Sized,
    {
        bincode::deserialize(bytes)
    }

    fn to_bytes(&self) -> Vec<u8>
        where
            Self: Sized,
    {
        bincode::serialize(self).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Packet {
    pub id: u8,
    pub data: Vec<u8>,
}

impl Serializable for Packet {}

impl Packet {
    pub fn new<T>(id: u8, data: T) -> Self
        where
            T: Serializable,
    {
        Packet {
            id,
            data: data.to_bytes(),
        }
    }

    pub fn encrypt(self, key: &Symmetric256Crypto) -> Result<EncryptedPacket, &str> {
        let result = key.encrypt(&self.data).ok();
        if result.is_none() {
            return Err("Failed to encrypt packet!")
        }
        let (nonce, encrypted) = result.unwrap();
        let nonce = nonce.to_vec();

        Ok(EncryptedPacket {
            id: self.id,
            data: encrypted,
            nonce,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedPacket {
    pub id: u8,
    data: Vec<u8>,
    nonce: Vec<u8>,
}

impl Serializable for EncryptedPacket {}

impl EncryptedPacket {
    pub fn decrypt(self, key: &Symmetric256Crypto) -> Result<Packet, &str> {
        let nonce = Nonce::from_slice(&self.nonce);
        let decrypted = key.decrypt(nonce, &self.data).ok();
        if decrypted.is_none() {
            return Err("Failed to decrypt packet!");
        }
        let decrypted = decrypted.unwrap();

        Ok(Packet {
            id: self.id,
            data: decrypted,
        })
    }

}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptData {
    pub public_key: Vec<u8>,
}

impl Serializable for EncryptData {}


#[derive(Serialize, Deserialize, Debug)]
pub struct MessageData {
    pub message: String,
}

impl Serializable for MessageData {}

