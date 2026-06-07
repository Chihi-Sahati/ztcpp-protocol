use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{info, error};

/// UDP listener for NHP protocol packets.
pub struct UdpListener {
    socket: UdpSocket,
    local_addr: SocketAddr,
}

impl UdpListener {
    /// Bind to the specified address and return a UDP listener.
    pub async fn bind(addr: SocketAddr) -> Result<Self, String> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| format!("Failed to bind UDP socket on {}: {}", addr, e))?;
        let local_addr = socket.local_addr()
            .map_err(|e| format!("Failed to get local address: {}", e))?;
        info!("UDP listener bound on {}", local_addr);
        Ok(Self { socket, local_addr })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get a reference to the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Receive a packet from the socket.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), String> {
        self.socket
            .recv_from(buf)
            .await
            .map_err(|e| format!("UDP recv failed: {}", e))
    }

    /// Send a packet to the specified address.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, String> {
        self.socket
            .send_to(buf, addr)
            .await
            .map_err(|e| format!("UDP send failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_and_recv() {
        let listener = UdpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        assert!(!listener.local_addr().to_string().is_empty());
    }
}
