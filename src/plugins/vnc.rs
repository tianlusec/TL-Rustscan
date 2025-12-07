use super::dicts::COMMON_PASSWORDS;
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use des::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use des::Des;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct VncPlugin;

#[async_trait]
impl ScanPlugin for VncPlugin {
    fn name(&self) -> &str {
        "VNC"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![5900, 5901]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let port = info.port.parse::<u16>().unwrap_or(5900);
        let addr = format!("{}:{}", info.host, port);
        let timeout = Duration::from_secs(3);

        let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        let mut buf = [0u8; 12];
        if tokio::time::timeout(timeout, stream.read_exact(&mut buf))
            .await
            .is_err()
        {
            return Ok(None);
        }

        if !buf.starts_with(b"RFB ") {
            return Ok(None);
        }

        if tokio::time::timeout(timeout, stream.write_all(&buf))
            .await
            .is_err()
        {
            return Ok(None);
        }

        let mut num_types = [0u8; 1];
        if tokio::time::timeout(timeout, stream.read_exact(&mut num_types))
            .await
            .is_err()
        {
            return Ok(None);
        }

        let count = num_types[0] as usize;
        if count == 0 {
            return Ok(None);
        }

        let mut types = vec![0u8; count];
        if tokio::time::timeout(timeout, stream.read_exact(&mut types))
            .await
            .is_err()
        {
            return Ok(None);
        }

        if types.contains(&1) {
            let msg = format!("[+] VNC No Auth detected on {}", addr);
            info!("{}", msg);
            return Ok(Some(msg));
        }

        if types.contains(&2) {
            if tokio::time::timeout(timeout, stream.write_all(&[2]))
                .await
                .is_err()
            {
                return Ok(None);
            }

            let mut challenge = [0u8; 16];
            if tokio::time::timeout(timeout, stream.read_exact(&mut challenge))
                .await
                .is_err()
            {
                return Ok(None);
            }

            for pass in COMMON_PASSWORDS {
                let mut stream2 =
                    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                        Ok(Ok(s)) => s,
                        _ => continue,
                    };
                if tokio::time::timeout(timeout, stream2.read_exact(&mut buf))
                    .await
                    .is_err()
                {
                    continue;
                }
                if tokio::time::timeout(timeout, stream2.write_all(&buf))
                    .await
                    .is_err()
                {
                    continue;
                }
                if tokio::time::timeout(timeout, stream2.read_exact(&mut num_types))
                    .await
                    .is_err()
                {
                    continue;
                }
                let mut t = vec![0u8; num_types[0] as usize];
                if tokio::time::timeout(timeout, stream2.read_exact(&mut t))
                    .await
                    .is_err()
                {
                    continue;
                }
                if tokio::time::timeout(timeout, stream2.write_all(&[2]))
                    .await
                    .is_err()
                {
                    continue;
                }
                let mut chal = [0u8; 16];
                if tokio::time::timeout(timeout, stream2.read_exact(&mut chal))
                    .await
                    .is_err()
                {
                    continue;
                }

                let response = encrypt_vnc_challenge(&chal, pass);

                if tokio::time::timeout(timeout, stream2.write_all(&response))
                    .await
                    .is_err()
                {
                    continue;
                }

                let mut result = [0u8; 4];
                if let Ok(Ok(_)) =
                    tokio::time::timeout(timeout, stream2.read_exact(&mut result)).await
                {
                    if result[0] == 0 && result[1] == 0 && result[2] == 0 && result[3] == 0 {
                        let msg = format!("[+] VNC 弱口令: {} -> {}", addr, pass);
                        info!("{}", msg);
                        return Ok(Some(msg));
                    }
                }
            }
        }

        Ok(None)
    }
}

fn encrypt_vnc_challenge(challenge: &[u8; 16], password: &str) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (i, &b) in password.as_bytes().iter().take(8).enumerate() {
        key[i] = reverse_bits(b);
    }

    let cipher = Des::new(GenericArray::from_slice(&key));
    let mut response = [0u8; 16];

    let mut block1 = GenericArray::clone_from_slice(&challenge[0..8]);
    let mut block2 = GenericArray::clone_from_slice(&challenge[8..16]);

    cipher.encrypt_block(&mut block1);
    cipher.encrypt_block(&mut block2);

    response[0..8].copy_from_slice(&block1);
    response[8..16].copy_from_slice(&block2);

    response
}

fn reverse_bits(mut b: u8) -> u8 {
    let mut r = 0;
    for _ in 0..8 {
        r <<= 1;
        if b & 1 != 0 {
            r |= 1;
        }
        b >>= 1;
    }
    r
}
