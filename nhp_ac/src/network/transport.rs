use crate::protocol::packet::{NhpPacket, NhpPacketType};

/// Transport layer for sending and receiving NHP packets over UDP.
pub struct NhpTransport;

impl NhpTransport {
    /// Encode an NhpPacket for network transmission.
    pub fn encode_packet(packet: &NhpPacket) -> Vec<u8> {
        packet.to_bytes()
    }

    /// Decode raw bytes into an NhpPacket.
    pub fn decode_packet(data: &[u8]) -> Result<NhpPacket, String> {
        NhpPacket::from_bytes(data)
    }

    /// Create a KNK request packet.
    pub fn create_knk_request(payload: &[u8], sequence: u32) -> NhpPacket {
        use bytes::Bytes;
        NhpPacket {
            packet_type: NhpPacketType::KnkRequest,
            payload: Bytes::copy_from_slice(payload),
            sequence,
        }
    }

    /// Create a session data packet.
    pub fn create_session_data(payload: &[u8], sequence: u32) -> NhpPacket {
        use bytes::Bytes;
        NhpPacket {
            packet_type: NhpPacketType::SessionData,
            payload: Bytes::copy_from_slice(payload),
            sequence,
        }
    }

    /// Create a heartbeat packet.
    pub fn create_heartbeat(sequence: u32) -> NhpPacket {
        NhpPacket {
            packet_type: NhpPacketType::Heartbeat,
            payload: bytes::Bytes::new(),
            sequence,
        }
    }

    /// Create a teardown packet.
    pub fn create_teardown(sequence: u32) -> NhpPacket {
        NhpPacket {
            packet_type: NhpPacketType::SessionTeardown,
            payload: bytes::Bytes::new(),
            sequence,
        }
    }
}
