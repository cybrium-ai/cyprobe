//! MAC OUI lookup — resolve manufacturer from MAC address prefix.
//!
//! Uses an embedded lookup table of ~500 common vendors (medical, OT, IT, networking).
//! For full IEEE OUI database, load from ~/.cyprobe/oui.txt at runtime.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Lookup vendor from MAC address (format: "aa:bb:cc:dd:ee:ff" or "AA:BB:CC:DD:EE:FF").
pub fn lookup(mac: &str) -> String {
    let prefix = mac_prefix(mac);
    OUI_DB.get(prefix.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "Unknown".to_string())
}

/// Classify device type from vendor name.
pub fn classify_vendor(vendor: &str) -> String {
    let v = vendor.to_lowercase();

    // Medical devices
    if v.contains("philips") && (v.contains("medical") || v.contains("health")) { return "medical".into() }
    if v.contains("ge healthcare") || v.contains("general electric medical") { return "medical".into() }
    if v.contains("siemens health") { return "medical".into() }
    if v.contains("baxter") || v.contains("bd ") || v.contains("becton") { return "medical".into() }
    if v.contains("medtronic") || v.contains("stryker") || v.contains("draeger") { return "medical".into() }
    if v.contains("hill-rom") || v.contains("hillrom") || v.contains("welch allyn") { return "medical".into() }
    if v.contains("masimo") || v.contains("nihon kohden") || v.contains("mindray") { return "medical".into() }

    // OT/ICS
    if v.contains("schneider") || v.contains("modicon") { return "plc".into() }
    if v.contains("rockwell") || v.contains("allen-bradley") { return "plc".into() }
    if v.contains("siemens") && !v.contains("health") { return "plc".into() }
    if v.contains("honeywell") || v.contains("johnson controls") || v.contains("tridium") { return "bms".into() }
    if v.contains("abb") || v.contains("emerson") || v.contains("yokogawa") { return "plc".into() }

    // Networking
    if v.contains("cisco") || v.contains("arista") || v.contains("juniper") { return "network".into() }
    if v.contains("aruba") || v.contains("ruckus") || v.contains("ubiquiti") { return "network".into() }
    if v.contains("fortinet") || v.contains("palo alto") || v.contains("sonicwall") { return "firewall".into() }

    // Printers
    if v.contains("hp ") && v.contains("print") || v.contains("xerox") || v.contains("lexmark") || v.contains("ricoh") { return "printer".into() }
    if v.contains("canon") || v.contains("epson") || v.contains("brother") { return "printer".into() }

    // Servers / workstations
    if v.contains("dell") || v.contains("lenovo") || v.contains("hewlett") { return "workstation".into() }
    if v.contains("supermicro") || v.contains("intel corp") { return "server".into() }

    // IoT
    if v.contains("raspberry") || v.contains("espressif") || v.contains("tuya") { return "iot".into() }

    // VoIP
    if v.contains("polycom") || v.contains("yealink") || v.contains("avaya") { return "voip".into() }

    // VMware
    if v.contains("vmware") { return "virtual".into() }

    "unknown".into()
}

/// Estimate Purdue level from vendor + device type.
pub fn estimate_purdue_level(vendor: &str, device_type: &str) -> Option<u8> {
    match device_type {
        "plc" => Some(0),
        "medical" => Some(1),
        "bms" => Some(2),
        "network" | "firewall" => Some(3),
        "server" => Some(4),
        "workstation" => Some(5),
        "printer" | "voip" => Some(3),
        _ => None,
    }
}

fn mac_prefix(mac: &str) -> String {
    mac.to_uppercase()
        .replace('-', ":")
        .chars()
        .take(8) // "AA:BB:CC"
        .collect()
}

// ── Embedded OUI database (top ~500 vendors) ─────────────────────────────────

static OUI_DB: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // Medical device manufacturers
    m.insert("00:09:FB", "Philips Medical Systems");
    m.insert("00:1E:8F", "Philips Healthcare");
    m.insert("00:21:A0", "Philips Medical Systems");
    m.insert("00:04:9F", "GE Healthcare");
    m.insert("00:17:23", "GE Healthcare");
    m.insert("00:1C:02", "GE Healthcare");
    m.insert("00:80:82", "GE Healthcare");
    m.insert("00:09:02", "Siemens Healthineers");
    m.insert("00:0B:49", "Siemens Healthineers");
    m.insert("00:1A:E8", "Siemens Healthineers");
    m.insert("00:30:AB", "Baxter International");
    m.insert("00:1C:F0", "BD (Becton Dickinson)");
    m.insert("00:17:EB", "BD (Becton Dickinson)");
    m.insert("00:0E:E5", "Medtronic");
    m.insert("00:A0:96", "Medtronic");
    m.insert("00:21:BA", "Stryker");
    m.insert("00:1D:B5", "Draeger Medical");
    m.insert("00:1E:C9", "Hill-Rom");
    m.insert("00:0A:EB", "Masimo");
    m.insert("00:90:C2", "Nihon Kohden");
    m.insert("00:22:A0", "Mindray Medical");
    m.insert("00:1F:53", "Welch Allyn");
    m.insert("00:26:B6", "Spacelabs Healthcare");
    m.insert("00:11:33", "Rauland-Borg (Nurse Call)");
    m.insert("00:05:5D", "Ascom");

    // OT/ICS manufacturers
    m.insert("00:80:F4", "Schneider Electric");
    m.insert("00:00:54", "Schneider Electric (Modicon)");
    m.insert("00:01:05", "Schneider Electric");
    m.insert("00:00:BC", "Rockwell Automation (Allen-Bradley)");
    m.insert("00:1D:9C", "Rockwell Automation");
    m.insert("00:0E:C6", "Siemens AG (Industrial)");
    m.insert("00:10:E3", "Siemens AG");
    m.insert("A4:BA:DB", "Honeywell");
    m.insert("00:40:84", "Honeywell");
    m.insert("00:50:C2", "Johnson Controls");
    m.insert("00:07:7C", "ABB");
    m.insert("00:0F:9F", "Emerson Process Management");
    m.insert("00:02:8A", "Yokogawa Electric");
    m.insert("00:C0:AA", "Omron Industrial");
    m.insert("00:20:4E", "Mitsubishi Electric");
    m.insert("00:30:11", "Tridium (Niagara)");
    m.insert("00:60:35", "Phoenix Contact");

    // Networking
    m.insert("00:00:0C", "Cisco Systems");
    m.insert("00:1A:2F", "Cisco Systems");
    m.insert("00:1B:54", "Cisco Systems");
    m.insert("00:22:55", "Cisco Systems");
    m.insert("00:25:84", "Cisco Systems");
    m.insert("F4:CF:E2", "Cisco Systems");
    m.insert("00:1A:1E", "Aruba Networks");
    m.insert("00:0B:86", "Aruba Networks");
    m.insert("24:DE:C6", "Aruba Networks");
    m.insert("00:24:6C", "Ruckus Wireless");
    m.insert("B4:75:0E", "Ruckus Wireless");
    m.insert("00:27:22", "Ubiquiti Networks");
    m.insert("24:A4:3C", "Ubiquiti Networks");
    m.insert("80:2A:A8", "Ubiquiti Networks");
    m.insert("00:1B:17", "Juniper Networks");
    m.insert("00:05:85", "Juniper Networks");
    m.insert("00:1C:73", "Arista Networks");
    m.insert("00:09:0F", "Fortinet");
    m.insert("00:90:0B", "Palo Alto Networks");
    m.insert("00:06:B1", "SonicWall");

    // Servers / workstations
    m.insert("00:25:64", "Dell");
    m.insert("14:FE:B5", "Dell");
    m.insert("F0:1F:AF", "Dell");
    m.insert("24:6E:96", "Dell");
    m.insert("00:17:A4", "Hewlett-Packard");
    m.insert("00:21:5A", "Hewlett-Packard");
    m.insert("3C:D9:2B", "Hewlett-Packard");
    m.insert("00:1E:68", "Lenovo");
    m.insert("00:06:1B", "Lenovo");
    m.insert("00:25:90", "Supermicro");
    m.insert("00:1E:67", "Intel Corporate");
    m.insert("A4:BF:01", "Intel Corporate");

    // VMware
    m.insert("00:0C:29", "VMware");
    m.insert("00:50:56", "VMware");
    m.insert("00:05:69", "VMware");

    // Microsoft Hyper-V
    m.insert("00:15:5D", "Microsoft Hyper-V");

    // Apple
    m.insert("00:03:93", "Apple");
    m.insert("3C:15:C2", "Apple");
    m.insert("A4:83:E7", "Apple");
    m.insert("F0:18:98", "Apple");

    // Printers
    m.insert("00:00:48", "Xerox");
    m.insert("00:1E:0B", "Hewlett-Packard (Printing)");
    m.insert("00:21:5C", "Ricoh");
    m.insert("00:00:85", "Canon");
    m.insert("00:26:AB", "Lexmark");

    // VoIP
    m.insert("00:04:F2", "Polycom");
    m.insert("00:15:65", "Yealink");
    m.insert("00:04:0D", "Avaya");
    m.insert("00:1B:4F", "Avaya");

    // IoT
    m.insert("B8:27:EB", "Raspberry Pi Foundation");
    m.insert("DC:A6:32", "Raspberry Pi Foundation");
    m.insert("E8:DB:84", "Raspberry Pi Foundation");
    m.insert("24:0A:C4", "Espressif (ESP32)");
    m.insert("A4:CF:12", "Espressif (ESP32)");
    m.insert("D8:F1:5B", "Tuya Smart");

    // BMS / Building
    m.insert("00:C0:C7", "Trane (HVAC)");
    m.insert("00:0D:4B", "Carrier (HVAC)");
    m.insert("00:40:9D", "Automated Logic");

    // ── Additional lookups from local network scan ──
    m.insert("9C:50:D1", "Murata Manufacturing");
    m.insert("8C:85:80", "Smart Innovation");
    m.insert("08:6A:C5", "Intel Corporate");
    m.insert("48:E1:E9", "Ezviz (Hikvision)");
    m.insert("68:C6:3A", "Samsung Electronics");
    m.insert("00:71:47", "Amazon Technologies");
    m.insert("54:2A:1B", "Samsung Electronics");
    m.insert("40:49:0F", "Hon Hai Precision (Foxconn)");
    m.insert("64:52:99", "The Chamberlain Group (MyQ)");
    m.insert("F0:45:DA", "LG Electronics");
    m.insert("48:B4:23", "Amazon Technologies");
    m.insert("2C:3A:E8", "Roku");
    m.insert("E0:4F:43", "Universal Global Scientific");
    m.insert("2C:CF:67", "Apple");
    m.insert("40:2F:86", "Google");
    m.insert("28:6B:B4", "Samsung Electronics");
    m.insert("9C:76:13", "Kyocera (Printer)");
    m.insert("CC:A7:C1", "Samsung Electronics");
    m.insert("F8:FF:C2", "Apple");
    m.insert("40:22:D8", "LG Electronics");
    m.insert("28:CF:51", "Rakuten (Kobo)");
    m.insert("CC:27:46", "Amazon Technologies");

    // ── Medical devices (expanded from IEEE OUI) ──
    m.insert("E4:75:1E", "Getinge (Sterilization)");
    m.insert("00:01:13", "Olympus Medical");
    m.insert("00:C0:D3", "Olympus Medical");
    m.insert("00:0E:31", "Olympus Medical");
    m.insert("00:16:86", "Karl Storz");
    m.insert("70:41:B7", "Edwards Lifesciences");
    m.insert("00:13:DD", "Abbott Diagnostics");
    m.insert("C0:A2:6D", "Abbott Point of Care");
    m.insert("58:42:E4", "Baxter International");
    m.insert("58:46:E1", "Baxter International");
    m.insert("9C:C8:AE", "Becton Dickinson");
    m.insert("00:0F:19", "Boston Scientific");
    m.insert("00:1D:4A", "Carestream Health");
    m.insert("44:4B:5D", "GE Healthcare");
    m.insert("D8:28:C9", "General Electric");
    m.insert("00:14:B8", "Hill-Rom");
    m.insert("00:10:5D", "Draeger Medical");
    m.insert("00:30:E6", "Draeger Medical Systems");
    m.insert("00:60:93", "Varian Medical");

    // ── Cisco (expanded — top 20 prefixes) ──
    m.insert("E8:0A:B9", "Cisco Systems");
    m.insert("48:1B:A4", "Cisco Systems");
    m.insert("6C:03:B5", "Cisco Systems");
    m.insert("90:88:55", "Cisco Systems");
    m.insert("68:71:61", "Cisco Systems");
    m.insert("4C:EC:0F", "Cisco Systems");
    m.insert("5C:64:F1", "Cisco Systems");
    m.insert("C8:28:E5", "Cisco Systems");
    m.insert("D0:09:C8", "Cisco Systems");
    m.insert("44:64:3C", "Cisco Systems");
    m.insert("24:16:1B", "Cisco Systems");
    m.insert("E8:DC:6C", "Cisco Systems");
    m.insert("34:B8:83", "Cisco Systems");
    m.insert("80:6A:00", "Cisco Systems");
    m.insert("AC:BC:D9", "Cisco Systems");
    m.insert("40:06:D5", "Cisco Systems");
    m.insert("08:45:D1", "Cisco Systems");
    m.insert("68:87:C6", "Cisco Systems");

    // ── Cisco Meraki ──
    m.insert("9C:E3:30", "Cisco Meraki");
    m.insert("B4:DF:91", "Cisco Meraki");
    m.insert("B8:AB:61", "Cisco Meraki");
    m.insert("08:F1:B3", "Cisco Meraki");
    m.insert("CC:9C:3E", "Cisco Meraki");

    // ── Fortinet / FortiGate ──
    m.insert("74:78:A6", "Fortinet");
    m.insert("84:39:8F", "Fortinet");
    m.insert("78:18:EC", "Fortinet");
    m.insert("5C:63:B0", "Fortinet");
    m.insert("AC:71:2E", "Fortinet");
    m.insert("04:01:A1", "Fortinet");
    m.insert("D4:B4:C0", "Fortinet");
    m.insert("1C:D1:1A", "Fortinet");
    m.insert("80:5A:70", "Fortinet");

    // ── Ubiquiti (expanded) ──
    m.insert("F0:9F:C2", "Ubiquiti Networks");
    m.insert("78:8A:20", "Ubiquiti Networks");
    m.insert("74:83:C2", "Ubiquiti Networks");
    m.insert("E0:63:DA", "Ubiquiti Networks");
    m.insert("24:5A:4C", "Ubiquiti Networks");
    m.insert("60:22:32", "Ubiquiti Networks");
    m.insert("E4:38:83", "Ubiquiti Networks");
    m.insert("0C:EA:14", "Ubiquiti Networks");
    m.insert("78:45:58", "Ubiquiti Networks");

    // ── HPE (servers, switches, storage) ──
    m.insert("14:02:EC", "HPE");
    m.insert("1C:98:EC", "HPE");
    m.insert("24:F2:7F", "HPE");
    m.insert("80:8D:B7", "HPE");
    m.insert("94:18:82", "HPE");
    m.insert("34:FC:B9", "HPE");
    m.insert("48:4A:E9", "HPE");
    m.insert("4C:AE:A3", "HPE");
    m.insert("20:A6:CD", "HPE");
    m.insert("70:3A:0E", "HPE");

    // ── HP Inc. (printers, workstations) ──
    m.insert("64:4E:D7", "HP Inc.");
    m.insert("7C:4D:8F", "HP Inc.");
    m.insert("5C:60:BA", "HP Inc.");
    m.insert("50:81:40", "HP Inc.");
    m.insert("F8:0D:AC", "HP Inc.");

    // ── Dell Technologies ──
    m.insert("D0:43:1E", "Dell Technologies");
    m.insert("00:C0:4F", "Dell Technologies");
    m.insert("00:B0:D0", "Dell Technologies");
    m.insert("00:19:B9", "Dell Technologies");
    m.insert("00:1A:A0", "Dell Technologies");
    m.insert("78:2B:CB", "Dell Technologies");
    m.insert("18:03:73", "Dell Technologies");

    // ── Juniper Networks ──
    m.insert("E4:F2:7C", "Juniper Networks");
    m.insert("60:C7:8D", "Juniper Networks");
    m.insert("3C:08:CD", "Juniper Networks");
    m.insert("48:5A:0D", "Juniper Networks");
    m.insert("84:B5:9C", "Juniper Networks");
    m.insert("5C:45:27", "Juniper Networks");
    m.insert("EC:3E:F7", "Juniper Networks");
    m.insert("00:21:59", "Juniper Networks");

    // ── Palo Alto Networks ──
    m.insert("60:15:2B", "Palo Alto Networks");
    m.insert("00:86:9C", "Palo Alto Networks");
    m.insert("08:30:6B", "Palo Alto Networks");
    m.insert("D4:F4:BE", "Palo Alto Networks");
    m.insert("F4:D5:8A", "Palo Alto Networks");

    // ── Arista Networks ──
    m.insert("FC:59:C0", "Arista Networks");
    m.insert("C4:CA:2B", "Arista Networks");
    m.insert("9C:69:ED", "Arista Networks");
    m.insert("B8:A1:B8", "Arista Networks");
    m.insert("A8:8F:99", "Arista Networks");

    // ── Ruckus Wireless ──
    m.insert("D4:BD:4F", "Ruckus Wireless");
    m.insert("5C:DF:89", "Ruckus Wireless");
    m.insert("38:45:3B", "Ruckus Wireless");
    m.insert("60:D0:2C", "Ruckus Wireless");
    m.insert("34:FA:9F", "Ruckus Wireless");

    // ── Storage (NetApp, QNAP, Pure Storage) ──
    m.insert("00:80:E5", "NetApp");
    m.insert("D0:39:EA", "NetApp");
    m.insert("00:A0:B8", "NetApp");
    m.insert("00:A0:98", "NetApp");
    m.insert("24:5E:BE", "QNAP Systems");
    m.insert("E8:43:B6", "QNAP Systems");
    m.insert("24:A9:37", "Pure Storage");

    // ── Firewalls (Sophos, WatchGuard, Check Point) ──
    m.insert("A8:91:62", "Sophos");
    m.insert("C8:4F:86", "Sophos");
    m.insert("00:1A:8C", "Sophos");
    m.insert("00:01:21", "WatchGuard");
    m.insert("00:1D:96", "WatchGuard");
    m.insert("00:90:7F", "WatchGuard");
    m.insert("00:A0:8E", "Check Point");
    m.insert("0C:52:7F", "Check Point");
    m.insert("00:1C:7F", "Check Point");

    // ── Extreme Networks / Brocade ──
    m.insert("08:EA:44", "Extreme Networks");
    m.insert("F4:EA:B5", "Extreme Networks");
    m.insert("B8:7C:F2", "Extreme Networks");
    m.insert("E0:A1:29", "Extreme Networks");
    m.insert("A8:C6:47", "Extreme Networks");
    m.insert("CC:4E:24", "Brocade");
    m.insert("00:E0:52", "Brocade");
    m.insert("00:01:0F", "Brocade");
    m.insert("BC:E9:E2", "Brocade");

    // ── MikroTik / Cambium / Cradlepoint ──
    m.insert("08:55:31", "MikroTik");
    m.insert("B8:69:F4", "MikroTik");
    m.insert("00:0C:42", "MikroTik");
    m.insert("F4:1E:57", "MikroTik");
    m.insert("78:9A:18", "MikroTik");
    m.insert("FC:11:65", "Cambium Networks");
    m.insert("BC:A9:93", "Cambium Networks");
    m.insert("00:04:56", "Cambium Networks");
    m.insert("00:30:44", "Cradlepoint");
    m.insert("00:E0:1C", "Cradlepoint");

    // Consumer / enterprise — common home + office devices
    m.insert("90:09:D0", "Synology");
    m.insert("00:11:32", "Synology");
    m.insert("6C:56:97", "Intel Corporate");
    m.insert("F8:75:A4", "Intel Corporate");
    m.insert("A0:36:9F", "Intel Corporate");
    m.insert("3C:22:FB", "Apple");
    m.insert("A8:60:B6", "Apple");
    m.insert("14:98:77", "Apple");
    m.insert("F0:D4:E2", "Apple");
    m.insert("BC:D0:74", "Apple");
    m.insert("AC:DE:48", "Apple");
    m.insert("38:F9:D3", "Apple");
    m.insert("C8:69:CD", "Apple");
    m.insert("DC:A9:04", "Apple");
    m.insert("9C:20:7B", "Apple");
    m.insert("A4:5E:60", "Apple");
    m.insert("60:F8:1D", "Apple");
    m.insert("B0:BE:83", "Apple");
    m.insert("78:7B:8A", "Apple");
    m.insert("88:66:A5", "Apple");
    m.insert("98:01:A7", "Apple");
    m.insert("3C:06:30", "Apple");
    m.insert("C0:D0:12", "Apple");
    m.insert("D0:D2:B0", "Apple");
    m.insert("28:6A:BA", "Apple");
    m.insert("E0:B5:5F", "Apple");
    m.insert("50:ED:3C", "Apple");
    m.insert("60:83:73", "Apple");
    m.insert("84:FC:FE", "Apple");
    m.insert("10:DD:B1", "Apple");
    m.insert("AC:BC:32", "Apple");
    m.insert("34:36:3B", "Apple");
    m.insert("70:56:81", "Apple");
    m.insert("CC:08:8D", "Apple");
    m.insert("F4:5C:89", "Apple");
    m.insert("54:26:96", "Apple");
    m.insert("00:1C:B3", "Apple");
    m.insert("D4:61:9D", "Apple");

    // Samsung
    m.insert("00:21:19", "Samsung");
    m.insert("00:26:37", "Samsung");
    m.insert("38:01:97", "Samsung");
    m.insert("78:52:1A", "Samsung");
    m.insert("D0:22:BE", "Samsung");
    m.insert("50:01:D9", "Samsung");
    m.insert("A8:7C:01", "Samsung");

    // Google
    m.insert("54:60:09", "Google");
    m.insert("F4:F5:D8", "Google");
    m.insert("30:FD:38", "Google");
    m.insert("A4:77:33", "Google");

    // Amazon
    m.insert("40:B4:CD", "Amazon (Echo/Fire)");
    m.insert("74:C2:46", "Amazon (Echo/Fire)");
    m.insert("68:54:FD", "Amazon (Echo/Fire)");
    m.insert("FC:65:DE", "Amazon (Echo/Fire)");

    // TP-Link
    m.insert("50:C7:BF", "TP-Link");
    m.insert("C0:06:C3", "TP-Link");
    m.insert("60:32:B1", "TP-Link");
    m.insert("EC:08:6B", "TP-Link");

    // Netgear
    m.insert("00:14:6C", "Netgear");
    m.insert("20:E5:2A", "Netgear");
    m.insert("C4:04:15", "Netgear");

    // Sonos
    m.insert("00:0E:58", "Sonos");
    m.insert("B8:E9:37", "Sonos");
    m.insert("48:A6:B8", "Sonos");

    // Ring / Nest
    m.insert("18:B4:30", "Nest (Google)");
    m.insert("64:16:66", "Nest (Google)");
    m.insert("F4:B8:5E", "Ring (Amazon)");

    // HP / Printers
    m.insert("00:1A:4B", "Hewlett-Packard");
    m.insert("10:60:4B", "Hewlett-Packard");
    m.insert("B0:5A:DA", "Hewlett-Packard");
    m.insert("2C:44:FD", "Hewlett-Packard");
    m.insert("94:57:A5", "Hewlett-Packard");

    m
});
