use bytes::Bytes;

/// NHP protocol packet structure.
#[derive(Debug, Clone)]
pub struct NhpPacket {
    pub packet_type: NhpPacketType,
    pub payload: Bytes,
    pub sequence: u32,
}

/// NHP packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NhpPacketType {
    KnkRequest = 0x01,
    KnkResponse = 0x02,
    SessionData = 0x03,
    SessionTeardown = 0x04,
    Heartbeat = 0x05,
    Error = 0xFF,
}

impl NhpPacket {
    /// Serialize a packet to bytes for network transmission.
    ///
    /// Format: [type: 1 byte][sequence: 4 bytes BE][length: 4 bytes BE][payload]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + self.payload.len());
        buf.push(self.packet_type as u8);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse a packet from network bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 9 {
            return Err(format!("Packet too short: {} bytes (minimum 9)", data.len()));
        }
        let packet_type = match data[0] {
            0x01 => NhpPacketType::KnkRequest,
            0x02 => NhpPacketType::KnkResponse,
            0x03 => NhpPacketType::SessionData,
            0x04 => NhpPacketType::SessionTeardown,
            0x05 => NhpPacketType::Heartbeat,
            0xFF => NhpPacketType::Error,
            _ => return Err(format!("Unknown packet type: 0x{:02X}", data[0])),
        };
        let sequence = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        if data.len() < 9 + length {
            return Err(format!(
                "Packet payload truncated: expected {} bytes, got {}",
                length,
                data.len() - 9
            ));
        }
        let payload = Bytes::copy_from_slice(&data[9..9 + length]);
        Ok(Self {
            packet_type,
            payload,
            sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let original = NhpPacket {
            packet_type: NhpPacketType::KnkRequest,
            payload: Bytes::from_static(b"hello world"),
            sequence: 42,
        };
        let bytes = original.to_bytes();
        let parsed = NhpPacket::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.packet_type, NhpPacketType::KnkRequest);
        assert_eq!(parsed.sequence, 42);
        assert_eq!(&parsed.payload[..], b"hello world");
    }

    #[test]
    fn test_empty_payload() {
        let packet = NhpPacket {
            packet_type: NhpPacketType::Heartbeat,
            payload: Bytes::new(),
            sequence: 1,
        };
        let bytes = packet.to_bytes();
        let parsed = NhpPacket::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.packet_type, NhpPacketType::Heartbeat);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_too_short() {
        let result = NhpPacket::from_bytes(b"\x01");
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_type() {
        let result = NhpPacket::from_bytes(b"\xFE\x00\x00\x00\x01\x00\x00\x00\x00");
        assert!(result.is_err());
    }
}
