use crate::common::{MessageType, receive_message, send_message};
use crate::crypto::{DiffieHellman, XorCipher};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use std::error::Error;

pub async fn run_client(server_addr: &str) -> Result<(), Box<dyn Error>> {
    println!("Connecting to server at {}...", server_addr);
    let stream = TcpStream::connect(server_addr).await?;
    println!("Connected to server!");

    let mut dh = DiffieHellman::new();
    
    let (mut reader, mut writer) = tokio::io::split(stream);
    
    let (msg_type, data) = receive_message(&mut reader).await?;
    if msg_type != MessageType::KeyExchange || data.len() != 8 {
        return Err("Invalid key exchange data from server".into());
    }
    
    let server_public_key = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
    ]);
    
    let client_public_key = dh.get_public_key();
    send_message(
        &mut writer, 
        MessageType::KeyExchange, 
        &client_public_key.to_le_bytes()
    ).await?;
    
    dh.compute_shared_secret(server_public_key);
    let key = dh.derive_key()?;
    let cipher = XorCipher::new(key);
    
    println!("Secure channel established!");
    println!("Available commands:");
    println!("  /list - Show online clients");
    println!("  /msg <client_id> <message> - Send a private message to a client");
    println!("  /exit - Disconnect from chat");
    println!("Any other text will be sent as a public message to all clients");
    
    let read_cipher = cipher.clone();
    
    let handle = tokio::spawn(async move {
        loop {
            match receive_message(&mut reader).await {
                Ok((MessageType::Data, encrypted_data)) => {
                    let decrypted = read_cipher.decrypt(&encrypted_data);
                    let message = String::from_utf8_lossy(&decrypted);
                    println!("\n{}", message);
                    print!("> ");
                    let _ = tokio::io::stdout().flush().await;
                },
                Ok((MessageType::ClientList, encrypted_data)) => {
                    let decrypted = read_cipher.decrypt(&encrypted_data);
                    let clients = String::from_utf8_lossy(&decrypted);
                    println!("\nOnline clients:\n{}", clients);
                    print!("> ");
                    let _ = tokio::io::stdout().flush().await;
                },
                Ok((MessageType::Disconnect, _)) => {
                    println!("\nServer disconnected");
                    break;
                },
                Err(e) => {
                    println!("\nError receiving message: {}", e);
                    break;
                },
                _ => {}
            }
        }
    });
    
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    
    loop {
        print!("> ");
        let _ = tokio::io::stdout().flush().await;
        
        line.clear();
        reader.read_line(&mut line).await?;
        let input = line.trim();
        
        if input.is_empty() {
            continue;
        }
        
        if input == "/exit" {
            send_message(&mut writer, MessageType::Disconnect, b"").await?;
            break;
        } else if input == "/list" {
            send_message(&mut writer, MessageType::ClientList, b"").await?;
        } else if input.starts_with("/msg ") {
            let parts: Vec<&str> = input.splitn(3, ' ').collect();
            if parts.len() < 3 {
                println!("Usage: /msg <client_id> <message>");
                continue;
            }
            
            let target_client = parts[1];
            let message = parts[2];
            
            let dm_command = format!("DM:{} {}", target_client, message);
            let encrypted = cipher.encrypt(dm_command.as_bytes());
            send_message(&mut writer, MessageType::Data, &encrypted).await?;
        } else {
            let encrypted = cipher.encrypt(input.as_bytes());
            send_message(&mut writer, MessageType::Data, &encrypted).await?;
        }
    }
    
    handle.abort();
    
    println!("Connection closed");
    Ok(())
}

impl Clone for XorCipher {
    fn clone(&self) -> Self {
        XorCipher {
            key: self.key.clone()
        }
    }
}
