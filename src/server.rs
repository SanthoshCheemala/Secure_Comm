use crate::common::{MessageType, receive_message, send_message};
use crate::crypto::{DiffieHellman, XorCipher};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use std::process;

type ClientId = String;

struct ClientMessage {
    sender: ClientId,
    content: Vec<u8>,
    exclude_sender: bool,
}

struct ServerState {
    clients: HashMap<ClientId, XorCipher>,
    tx: mpsc::Sender<ClientMessage>,
}

type ServerStateRef = Arc<Mutex<ServerState>>;

pub async fn run_server(port: u16) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind to port {}: {}", port, e);
            eprintln!("The port may already be in use. Try another port.");
            process::exit(1);
        }
    };
    
    println!("Server listening on {}", addr);

    let (tx, mut rx) = mpsc::channel::<ClientMessage>(100);
    
    let server_state = Arc::new(Mutex::new(ServerState {
        clients: HashMap::new(),
        tx: tx.clone(),
    }));
    
    let broadcast_state = server_state.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let state = broadcast_state.lock().await;
            
            for (client_id, cipher) in &state.clients {
                if msg.exclude_sender && *client_id == msg.sender {
                    continue;
                }
            }
        }
    });

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from: {}", addr);
                let client_id = addr.to_string();
                let state_clone = server_state.clone();
                tokio::spawn(handle_client(stream, client_id, state_clone));
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }
}

async fn handle_client(stream: TcpStream, client_id: ClientId, server: ServerStateRef) -> io::Result<()> {
    let mut dh = DiffieHellman::new();
    let server_public_key = dh.get_public_key();

    let (mut reader, mut writer) = tokio::io::split(stream);

    send_message(
        &mut writer, 
        MessageType::KeyExchange, 
        &server_public_key.to_le_bytes()
    ).await?;
    
    let (msg_type, data) = receive_message(&mut reader).await?;
    if msg_type != MessageType::KeyExchange || data.len() != 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid key exchange data"));
    }
    
    let client_public_key = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
    ]);
    
    dh.compute_shared_secret(client_public_key);
    let key = dh.derive_key().unwrap();
    let cipher = XorCipher::new(key);
    
    {
        let mut state = server.lock().await;
        state.clients.insert(client_id.clone(), cipher.clone());
        
        let message = format!("* New client connected: {}", client_id);
        let _ = state.tx.send(ClientMessage {
            sender: client_id.clone(),
            content: message.into_bytes(),
            exclude_sender: true,
        }).await;
    }
    
    println!("Secure channel established with {}", client_id);
    
    let welcome = format!("Welcome! You are connected as {}. There are {} other clients online.", 
        client_id, server.lock().await.clients.len() - 1);
    let encrypted = cipher.encrypt(welcome.as_bytes());
    send_message(&mut writer, MessageType::Data, &encrypted).await?;
    
    loop {
        match receive_message(&mut reader).await {
            Ok((msg_type, encrypted_data)) => {
                match msg_type {
                    MessageType::Data => {
                        let decrypted = cipher.decrypt(&encrypted_data);
                        let message = String::from_utf8_lossy(&decrypted);
                        println!("Message from {}: {}", client_id, message);
                        
                        let tx = server.lock().await.tx.clone();
                        let relay_msg = format!("{}: {}", client_id, message);
                        let _ = tx.send(ClientMessage {
                            sender: client_id.clone(),
                            content: relay_msg.into_bytes(),
                            exclude_sender: true,
                        }).await;
                        
                        let ack = "Message received";
                        let encrypted = cipher.encrypt(ack.as_bytes());
                        send_message(&mut writer, MessageType::Data, &encrypted).await?;
                    },
                    MessageType::Disconnect => {
                        println!("Client {} disconnected", client_id);
                        break;
                    },
                    _ => {
                        println!("Unexpected message type from {}", client_id);
                    }
                }
            },
            Err(e) => {
                println!("Client {} disconnected: {}", client_id, e);
                break;
            }
        };
    }
    
    {
        let mut state = server.lock().await;
        state.clients.remove(&client_id);
        
        let message = format!("* Client disconnected: {}", client_id);
        let _ = state.tx.send(ClientMessage {
            sender: client_id.clone(),
            content: message.into_bytes(),
            exclude_sender: true,
        }).await;
    }
    
    Ok(())
}
