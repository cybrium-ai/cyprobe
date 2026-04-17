pub mod modbus;
pub mod dnp3;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtAsset {
    pub kind: AssetKind,
    pub ip: String,
    pub port: u16,
    pub protocol: Protocol,
    pub unit_id: Option<u16>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub firmware: Option<String>,
    pub serial: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub passive_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Plc,
    Rtu,
    Hmi,
    ScadaGateway,
    Historian,
    EngineeringWs,
    IoTGateway,
    Sensor,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    ModbusTcp,
    ModbusRtu,
    Dnp3,
    S7comm,
    OpcUa,
    BacnetIp,
    EthernetIp,
    Iec104,
    Mqtt,
    Unknown,
}

impl Protocol {
    pub fn from_port(port: u16) -> Self {
        match port {
            502 => Self::ModbusTcp,
            20000 => Self::Dnp3,
            102 => Self::S7comm,
            4840 => Self::OpcUa,
            47808 => Self::BacnetIp,
            44818 => Self::EthernetIp,
            2404 => Self::Iec104,
            1883 | 8883 => Self::Mqtt,
            _ => Self::Unknown,
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::ModbusTcp => 502,
            Self::ModbusRtu => 502,
            Self::Dnp3 => 20000,
            Self::S7comm => 102,
            Self::OpcUa => 4840,
            Self::BacnetIp => 47808,
            Self::EthernetIp => 44818,
            Self::Iec104 => 2404,
            Self::Mqtt => 1883,
            Self::Unknown => 0,
        }
    }
}
