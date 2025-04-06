mod client;
mod common;
mod crypto;
mod server;

use std::env;
use tokio::runtime::Runtime;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} [client|server] [options]", args[0]);
        return;
    }

    let rt = Runtime::new().unwrap();

    match args[1].as_str() {
        "server" => {
            let port = args.get(2).map(|p| p.parse::<u16>().unwrap_or(8080)).unwrap_or(8080);
            rt.block_on(server::run_server(port));
        }
        "client" => {
            if args.len() < 3 {
                println!("Usage: {} client <server_address:port>", args[0]);
                return;
            }
            if let Err(e) = rt.block_on(client::run_client(&args[2])) {
                eprintln!("Client error: {}", e);
            }
        }
        _ => {
            println!("Unknown command. Use 'server' or 'client'");
        }
    }
}
