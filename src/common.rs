use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, PartialEq)]
pub enum MessageType {
    KeyExchange,
    Data,
    Disconnect,
    ClientList,
}

pub async fn send_message<W: AsyncWriteExt + Unpin>(writer: &mut W, msg_type: MessageType, data: &[u8]) -> io::Result<()> {
    let type_byte = match msg_type {
        MessageType::KeyExchange => 1u8,
        MessageType::Data => 2u8,
        MessageType::Disconnect => 3u8,
        MessageType::ClientList => 4u8,
    };
    
    let len = data.len() as u32;
    writer.write_u8(type_byte).await?;
    writer.write_u32(len).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    
    Ok(())
}

pub async fn receive_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<(MessageType, Vec<u8>)> {
    let type_byte = reader.read_u8().await?;
    let len = reader.read_u32().await? as usize;
    
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await?;
    
    let msg_type = match type_byte {
        1 => MessageType::KeyExchange,
        2 => MessageType::Data,
        3 => MessageType::Disconnect,
        4 => MessageType::ClientList,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown message type")),
    };
    
    Ok((msg_type, buffer))
}
