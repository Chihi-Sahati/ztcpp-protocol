use bytes::Bytes;

/// HTTP/2 Custom Frame Extension for NHP-SBA SAT Tokens
/// Frame Type: 0x1A
pub struct NhpSbaHttp2Frame {
    pub payload: Bytes,
    pub stream_id: u32,
}

impl NhpSbaHttp2Frame {
    pub fn new(stream_id: u32, payload: Bytes) -> Self {
        Self { payload, stream_id }
    }

    /// Serialize the custom frame to bytes
    /// 
    /// HTTP/2 Frame Format:
    /// Length: 24 bits
    /// Type: 8 bits (0x1A)
    /// Flags: 8 bits (0x00)
    /// Stream Identifier: 31 bits
    /// Frame Payload: Variable
    pub fn to_bytes(&self) -> Vec<u8> {
        let length = self.payload.len() as u32;
        let mut frame = Vec::with_capacity(9 + length as usize);

        // 24-bit Length
        frame.push(((length >> 16) & 0xFF) as u8);
        frame.push(((length >> 8) & 0xFF) as u8);
        frame.push((length & 0xFF) as u8);

        // 8-bit Type (0x1A)
        frame.push(0x1A);

        // 8-bit Flags (0x00)
        frame.push(0x00);

        // 31-bit Stream ID (MSB is reserved and must be 0)
        let stream_id = self.stream_id & 0x7FFFFFFF;
        frame.extend_from_slice(&stream_id.to_be_bytes());

        // Payload
        frame.extend_from_slice(&self.payload);

        frame
    }

    /// Parse an HTTP/2 frame
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 9 {
            return Err("Frame too short".to_string());
        }

        let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = data[3];

        if frame_type != 0x1A {
            return Err(format!("Expected frame type 0x1A, got 0x{:02X}", frame_type));
        }

        let stream_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF;

        if data.len() < 9 + length as usize {
            return Err("Frame payload truncated".to_string());
        }

        let payload = Bytes::copy_from_slice(&data[9..9 + length as usize]);

        Ok(Self { payload, stream_id })
    }
}
