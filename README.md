# Secure Communication

A secure messaging application built in Rust that enables encrypted communication between clients through a central relay server.

## Features

- End-to-end encryption using Diffie-Hellman key exchange
- Secure message relay between multiple clients
- Support for public and private messaging
- XOR-based encryption for message confidentiality
- Built with asynchronous I/O using Tokio

## Requirements

- Rust 1.54.0 or higher
- Cargo package manager

## Dependencies

- tokio = { version = "1.28.0", features = ["full"] }
- rand = "0.8.5"

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure_comm
```

2. Build the application:
```bash
cargo build --release
```

## Usage

### Starting the Server

```bash
cargo run server [port]
```

Where `port` is optional and defaults to 8080.

### Connecting as a Client

```bash
cargo run client <server_address:port>
```

Example:
```bash
cargo run client 127.0.0.1:8080
```

### Client Commands

Once connected, you can use the following commands:

- `/list` - Show all online clients
- `/msg <client_id> <message>` - Send a private message to a specific client
- `/exit` - Disconnect from the server
- Any other text is sent as a public message to all connected clients

## How It Works

1. When a client connects, the server and client perform a Diffie-Hellman key exchange
2. The shared secret is used to derive an encryption key
3. All subsequent messages are encrypted using XOR cipher with this key
4. The server relays messages between clients, allowing for multi-user chat
5. Each client maintains its own encryption key, ensuring message confidentiality

## Project Structure

- `src/main.rs` - Entry point, command-line argument parsing
- `src/client.rs` - Client implementation for connecting to the server
- `src/server.rs` - Server implementation for relaying messages between clients
- `src/crypto.rs` - Cryptographic primitives (Diffie-Hellman, XOR cipher)
- `src/common.rs` - Shared code for messaging protocol

## Security Considerations

This project is intended as a demonstration and educational tool. The cryptographic implementation uses simplified algorithms and should not be used in production environments without significant enhancements:

- The Diffie-Hellman implementation uses small prime numbers for demonstration
- XOR cipher is not secure for production use
- There's no authentication of clients or message integrity verification

## License

[MIT License]
