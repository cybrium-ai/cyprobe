use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use super::{AssetKind, OtAsset, Protocol};

const MODBUS_PORT: u16 = 502;
const TIMEOUT: Duration = Duration::from_secs(5);

// Modbus TCP MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
const MBAP_HEADER_LEN: usize = 7;

#[derive(Debug)]
pub struct ModbusFrame {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub data: Vec<u8>,
}

impl ModbusFrame {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < MBAP_HEADER_LEN + 1 {
            return None;
        }
        let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
        let protocol_id = u16::from_be_bytes([buf[2], buf[3]]);
        if protocol_id != 0 {
            return None; // not Modbus
        }
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let unit_id = buf[6];
        let function_code = buf[7];
        let data = buf[8..].to_vec();
        Some(Self {
            transaction_id,
            protocol_id,
            length,
            unit_id,
            function_code,
            data,
        })
    }

    pub fn is_modbus(buf: &[u8]) -> bool {
        if buf.len() < MBAP_HEADER_LEN + 1 {
            return false;
        }
        let protocol_id = u16::from_be_bytes([buf[2], buf[3]]);
        protocol_id == 0
    }
}

/// Build a Modbus Read Device Identification request (FC 0x2B, MEI 0x0E).
/// Object ID 0x00 = Basic identification (VendorName, ProductCode, Revision).
fn build_device_id_request(unit_id: u8, transaction_id: u16) -> Vec<u8> {
    let function_code: u8 = 0x2B; // Encapsulated Interface Transport
    let mei_type: u8 = 0x0E; // Read Device Identification
    let read_device_id_code: u8 = 0x01; // Basic
    let object_id: u8 = 0x00;

    let pdu = [function_code, mei_type, read_device_id_code, object_id];
    let length = (pdu.len() + 1) as u16; // +1 for unit_id

    let mut frame = Vec::with_capacity(MBAP_HEADER_LEN + pdu.len());
    frame.extend_from_slice(&transaction_id.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // protocol_id = 0
    frame.extend_from_slice(&length.to_be_bytes());
    frame.push(unit_id);
    frame.extend_from_slice(&pdu);
    frame
}

#[derive(Debug, Default)]
pub struct DeviceIdentity {
    pub vendor: Option<String>,
    pub product_code: Option<String>,
    pub revision: Option<String>,
}

fn parse_device_id_response(data: &[u8]) -> Option<DeviceIdentity> {
    // Response: MEI(1) + ReadDevIdCode(1) + ConformityLevel(1) + MoreFollows(1)
    //         + NextObjectId(1) + NumberOfObjects(1) + objects...
    if data.len() < 6 {
        return None;
    }
    if data[0] != 0x0E {
        return None;
    }
    let num_objects = data[5] as usize;
    let mut identity = DeviceIdentity::default();
    let mut offset = 6;

    for _ in 0..num_objects {
        if offset + 2 > data.len() {
            break;
        }
        let obj_id = data[offset];
        let obj_len = data[offset + 1] as usize;
        offset += 2;
        if offset + obj_len > data.len() {
            break;
        }
        let value = String::from_utf8_lossy(&data[offset..offset + obj_len]).to_string();
        match obj_id {
            0x00 => identity.vendor = Some(value),
            0x01 => identity.product_code = Some(value),
            0x02 => identity.revision = Some(value),
            _ => {}
        }
        offset += obj_len;
    }
    Some(identity)
}

/// Active probe: send a Modbus Device Identification request.
pub async fn probe_device(addr: SocketAddr) -> Result<OtAsset> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut stream = timeout(TIMEOUT, TcpStream::connect(addr)).await??;

    let request = build_device_id_request(0, 1);
    timeout(TIMEOUT, stream.write_all(&request)).await??;

    let mut buf = [0u8; 512];
    let n = timeout(TIMEOUT, stream.read(&mut buf)).await??;

    let mut asset = OtAsset {
        kind: AssetKind::Plc,
        ip: addr.ip().to_string(),
        port: addr.port(),
        protocol: Protocol::ModbusTcp,
        unit_id: Some(0),
        vendor: None,
        product: None,
        firmware: None,
        serial: None,
        first_seen: now.clone(),
        last_seen: now,
        passive_only: false,
    };

    if let Some(frame) = ModbusFrame::parse(&buf[..n]) {
        asset.unit_id = Some(frame.unit_id as u16);
        if frame.function_code == 0x2B {
            if let Some(identity) = parse_device_id_response(&frame.data) {
                asset.vendor = identity.vendor;
                asset.product = identity.product_code;
                asset.firmware = identity.revision;
            }
        }
    }

    Ok(asset)
}

/// Passive: check if a captured TCP payload looks like Modbus traffic.
pub fn classify_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Option<(u8, u8)> {
    if src_port != MODBUS_PORT && dst_port != MODBUS_PORT {
        return None;
    }
    let frame = ModbusFrame::parse(payload)?;
    Some((frame.unit_id, frame.function_code))
}
