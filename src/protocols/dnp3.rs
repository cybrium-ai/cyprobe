use super::{AssetKind, OtAsset, Protocol};

const DNP3_PORT: u16 = 20000;
const DNP3_START_BYTES: [u8; 2] = [0x05, 0x64];

#[derive(Debug)]
pub struct Dnp3Frame {
    pub start: u16,
    pub length: u8,
    pub control: u8,
    pub destination: u16,
    pub source: u16,
}

impl Dnp3Frame {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 10 {
            return None;
        }
        if buf[0] != DNP3_START_BYTES[0] || buf[1] != DNP3_START_BYTES[1] {
            return None;
        }
        Some(Self {
            start: u16::from_be_bytes([buf[0], buf[1]]),
            length: buf[2],
            control: buf[3],
            destination: u16::from_le_bytes([buf[4], buf[5]]),
            source: u16::from_le_bytes([buf[6], buf[7]]),
        })
    }

    pub fn is_dnp3(buf: &[u8]) -> bool {
        buf.len() >= 2 && buf[0] == DNP3_START_BYTES[0] && buf[1] == DNP3_START_BYTES[1]
    }
}

pub fn classify_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Option<(u16, u16)> {
    if src_port != DNP3_PORT && dst_port != DNP3_PORT {
        return None;
    }
    let frame = Dnp3Frame::parse(payload)?;
    Some((frame.source, frame.destination))
}

pub fn asset_from_passive(ip: &str, port: u16, source_addr: u16) -> OtAsset {
    let now = chrono::Utc::now().to_rfc3339();
    OtAsset {
        kind: AssetKind::Rtu,
        ip: ip.to_string(),
        port,
        protocol: Protocol::Dnp3,
        unit_id: Some(source_addr),
        vendor: None,
        product: None,
        firmware: None,
        serial: None,
        first_seen: now.clone(),
        last_seen: now,
        passive_only: true,
    }
}
