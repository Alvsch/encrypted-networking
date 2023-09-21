use std::collections::HashMap;
use std::io::Error;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use cryptography::asymmetric::AsymmetricKeyPair;
use cryptography::symmetric::Symmetric256Crypto;
use cryptography::{ECDH_P256, SystemRandom, UnparsedPublicKey};
use log::{debug, warn};
use tokio::net::UdpSocket;
use crate::packets::{EncryptData, EncryptedPacket, Packet, Serializable};

pub type ConnectionHandler = fn(socket: &Arc<UdpSocket>, connection: &Connection, packet: Packet);

pub struct Connection {
    pub address: SocketAddr,
    pub key: Option<Arc<Symmetric256Crypto>>,
}

impl Connection {
    pub fn is_encrypted(&self) -> bool {
        self.key.is_some()
    }
}

pub struct Server {
    socket: Arc<UdpSocket>,
    connections: HashMap<SocketAddr, Connection>,
}

impl Server {
    pub async fn new(address: &str) -> Result<Self, Error> {
        let socket = UdpSocket::bind(address).await?;
        let socket = Arc::new(socket);

        Ok(Self {
            socket,
            connections: HashMap::new(),
        })
    }

    pub fn get_connection(&self, address: &SocketAddr) -> Option<&Connection> {
        self.connections.get(address)
    }

    pub fn get_mut_connection(&mut self, address: &SocketAddr) -> Option<&mut Connection> {
        self.connections.get_mut(address)
    }

    pub async fn start_listener(&mut self, callback: ConnectionHandler) -> Result<(), Error> {
        loop {
            let mut buffer = [0u8; 1024];
            let (size, address) = self.socket.recv_from(&mut buffer).await?;
            let data = buffer[..size].to_vec();
            debug!("Received {} bytes from {}", size, address);

            let connection = self.connections.get_mut(&address);
            if connection.is_none() {
                let result = self.handle_handshake(address, &data).await.ok();
                if result.is_none() {
                    warn!("Failed to deserialize handshake from {}", address);
                }
                continue;
            }
            let connection = connection.unwrap();

            if !connection.is_encrypted() {
                let result = Server::encrypt_connection(&self.socket, connection, &data).await.ok();
                if result.is_none() {
                    warn!("Failed to encrypt connection with {}", address);
                }
                continue;
            }
            let key = connection.key.clone().unwrap();

            let encrypted = EncryptedPacket::from_bytes(&data).ok();
            if encrypted.is_none() {
                warn!("Failed to deserialize packet from {}", address);
                continue;
            }
            let encrypted = encrypted.unwrap();

            let decrypted = encrypted.decrypt(&key).ok();
            if decrypted.is_none() {
                warn!("Failed to decrypt packet from {}", address);
                continue;
            }
            let decrypted = decrypted.unwrap();

            callback(&self.socket, connection.deref(), decrypted);
        }
    }

    async fn handle_handshake(&mut self, address: SocketAddr, data: &[u8]) -> Result<(), bincode::Error> {
        let connection = Connection { address, key: None };
        let packet = Packet::from_bytes(data)?;
        if packet.id != 1 {
            return Ok(());
        }
        self.connections.insert(address, connection);
        Ok(())
    }

    async fn encrypt_connection(socket: &Arc<UdpSocket>, connection: &mut Connection, data: &[u8]) -> Result<(), bincode::Error> {
        let packet = Packet::from_bytes(data)?;
        if packet.id != 2 {
            return Ok(());
        }
        let encrypt = EncryptData::from_bytes(&packet.data)?;
        let key_pair = AsymmetricKeyPair::generate_keys(&SystemRandom::new());

        let result = key_pair.generate_shared_secret(
            &UnparsedPublicKey::new(&ECDH_P256, &encrypt.public_key[..])
        ).ok();
        if result.is_none() {
            warn!("Failed to generate shared secret with {}", connection.address);
            // TODO Return as error result
            return Ok(())
        }

        let (shared_secret, public_key) = result.unwrap();

        // Create a response packet containing the servers public key
        let response = Packet {
            id: 1,
            data: EncryptData {
                public_key: public_key.as_ref().to_vec(),
            }.to_bytes(),
        };

        // Send the response packet to the server
        socket.send_to(
            &response.to_bytes(),
            connection.address
        ).await.unwrap();
        debug!("Sent {:?}, to {}", response, connection.address);

        let key = Symmetric256Crypto::new(shared_secret.to_vec());
        connection.key = Some(Arc::new(key));

        Ok(())
    }

}