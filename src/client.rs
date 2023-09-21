use cryptography::asymmetric::AsymmetricKeyPair;
use cryptography::symmetric::Symmetric256Crypto;
use cryptography::{ECDH_P256, SystemRandom, UnparsedPublicKey};
use log::debug;
use tokio::net::UdpSocket;
use crate::packets::{EncryptData, EncryptedPacket, Packet, Serializable};

pub struct Client {
    socket: UdpSocket,
    pub key: Option<Symmetric256Crypto>,
}

impl Client {
    pub async fn new(address: &str) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(address).await?;

        let mut client = Self {
            socket,
            key: None,
        };

        client.handshake().await.unwrap();
        client.encrypt_connection().await.unwrap();

        Ok(client)
    }

    async fn handshake(&self) -> Result<(), std::io::Error> {
        let packet = Packet { id: 1, data: Vec::new() };
        self.send(packet).await?;
        Ok(())
    }

    async fn encrypt_connection(&mut self) -> Result<(), std::io::Error> {
        let key_pair = AsymmetricKeyPair::generate_keys(&SystemRandom::new());

        let packet = Packet {
            id: 2,
            data: EncryptData {
                public_key: key_pair.public_key.as_ref().to_vec(),
            }.to_bytes(),
        };

        self.send(packet).await?;

        let packet = self.receive().await?;
        let data = EncryptData::from_bytes(&packet.data).unwrap();

        let public_key = UnparsedPublicKey::new(
            &ECDH_P256,
            &data.public_key[..],
        );

        let (shared_secret, _) = key_pair.generate_shared_secret(&public_key).unwrap();
        let key = Symmetric256Crypto::new(shared_secret.to_vec());

        self.key = Some(key);
        Ok(())
    }

    pub async fn receive(&self) -> Result<Packet, std::io::Error> {
        let mut buffer = [0u8; 1024];
        let size = self.socket.recv(&mut buffer).await.unwrap();
        let data = buffer[..size].to_vec();

        if self.key.is_none() {
            let packet = Packet::from_bytes(&data).unwrap();
            debug!("Received {:?} from server", packet);
            return Ok(packet);
        }
        let encrypted = EncryptedPacket::from_bytes(&data).unwrap();
        let packet = encrypted.decrypt(self.key.as_ref().unwrap()).unwrap();
        debug!("Received {:?} from server", packet);

        Ok(packet)
    }

    pub async fn send(&self, packet: Packet) -> Result<(), std::io::Error> {
        if self.key.is_none() {
            self.socket.send(&packet.to_bytes()).await.unwrap();
            debug!("Sent {:?} to server", packet);
            return Ok(())
        }
        debug!("Sending {:?} to server", packet);
        let encrypted = packet.encrypt(self.key.as_ref().unwrap()).unwrap();
        self.socket.send(&encrypted.to_bytes()).await.unwrap();
        Ok(())
    }
}