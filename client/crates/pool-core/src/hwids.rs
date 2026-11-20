//! Hardware identifiers (node-protocol 1.2.0 section 4).
//!
//! * **What.** `HwIdentifiers` (`pool/hw-ids/v1`): EK hash, GPU UUIDs (NVML), SMBIOS UUID, board and disk serials,
//!   OS install id, physical NICs (MAC, kind, permanent flag, masked `mac_display`), VM indicators. Signed by the
//!   device key and sent **only to the server** (`POST /v1/devices` `hw_ids`, weekly `POST /v1/devices/{id}/hw-ids`).
//! * **Consent first.** Nothing is collected or sent before the in-app `hw_identifiers` consent ([`CONSENT_TEXT`]).
//!   Refusing blocks enrollment with an honest message.
//! * **Filters.** No locally administered (randomized) MACs; no Hyper-V, VMware, VirtualBox, Docker, WSL, VPN TAP/TUN,
//!   Bluetooth PAN or other virtual adapters; placeholder serials (`To be filled by O.E.M.`, all zeros, ...) dropped.
//! * **Never stored or logged raw.** Raw values live in memory for one request: `HwIdentifiers` has a redacting
//!   `Debug`, nothing here logs a value, `state.json` keeps only timestamps, and the agent turns off crash-dump heap
//!   capture ([`disable_crash_dumps`]). `tests/hw_ids.rs` greps the data dir and the logs for sentinel values.

use std::sync::Arc;

use pool_proto::objects::{mac_display, mac_is_locally_administered, HwIdentifiers, HwNic};

/// The in-app consent (kind `hw_identifiers`). Same version and text as face's consent registry
/// (`web/lib/content/onboarding.ts`, `CONSENTS.hw_identifiers`), so `text_sha256` matches the signed-off text.
pub const CONSENT_VERSION: &str = "2026-11-19.draft-2";
pub const CONSENT_TEXT: &str = "The desktop app sends identifiers of this computer's hardware (security chip, graphics card, board, disk, network adapters) to Vouch Compute so that one physical machine counts as one device. We keep only keyed fingerprints of them, never the raw values such as MAC addresses or serial numbers. Withdrawing this stops further reports, and a device without it cannot be enrolled for paid work.";

/// Lower-case hex SHA-256 of [`CONSENT_TEXT`] (`hw_consent.text_sha256`).
pub fn consent_text_sha256() -> String {
    hex::encode(pool_proto::sha256(CONSENT_TEXT.as_bytes()))
}

/// What the user sees when they refuse (enrollment is blocked; nothing was collected).
pub const REFUSED_MESSAGE: &str = "Vouch Compute can't register this computer for paid work without the hardware check. It makes sure one physical machine counts as one device. Nothing was collected or sent. You can change your mind at any time in the app.";

/// Weekly report interval, and the minimum gap between failed attempts.
pub const REPORT_INTERVAL_MS: u64 = 7 * 24 * 3600 * 1000;
pub const RETRY_GAP_MS: u64 = 3600 * 1000;

/// A weekly report is due: consent given, enrolled, a week since the last successful report (enrollment counts as
/// one), and no failed attempt within the last hour.
pub fn report_due(consent: bool, enrolled: bool, last_sent_ms: Option<u64>, last_attempt_ms: Option<u64>, now_ms: u64) -> bool {
    consent
        && enrolled
        && last_sent_ms.is_none_or(|t| now_ms.saturating_sub(t) >= REPORT_INTERVAL_MS)
        && last_attempt_ms.is_none_or(|t| now_ms.saturating_sub(t) >= RETRY_GAP_MS)
}

// ------------------------------------------------------------------ raw readings and filters

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Medium {
    Ethernet,
    Wifi,
    Bluetooth,
    Loopback,
    Tunnel,
    #[default]
    Other,
}

/// One adapter as the OS reports it (before filtering).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RawNic {
    pub name: String,
    pub description: String,
    /// Current address.
    pub mac: Option<[u8; 6]>,
    /// Burned-in address, when the OS reports it (Windows `PermanentAddress`, Linux `addr_assign_type == 0`).
    pub permanent_mac: Option<[u8; 6]>,
    pub medium: Medium,
    /// The OS says the adapter is virtual (Windows `Virtual`, Linux `/sys/devices/virtual`).
    pub virtual_: bool,
    /// Backed by hardware (Windows `HardwareInterface`, Linux `device` link). Unknown counts as `true`.
    pub hardware: bool,
}

impl std::fmt::Debug for RawNic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawNic").field("name", &self.name).field("medium", &self.medium).field("virtual", &self.virtual_).finish_non_exhaustive()
    }
}

/// Everything the OS reported, before filtering. Lives in memory only; `Debug` is redacted.
#[derive(Clone, Default)]
pub struct RawHw {
    pub smbios_uuid: Option<String>,
    pub board_serial: Option<String>,
    pub disk_serial: Option<String>,
    pub os_install_id: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub gpu_uuids: Vec<String>,
    pub nics: Vec<RawNic>,
    /// Running in a container (Docker, containerd, Kubernetes).
    pub container: bool,
    /// Running under WSL.
    pub wsl: bool,
}

impl std::fmt::Debug for RawHw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawHw").field("nics", &self.nics.len()).field("gpus", &self.gpu_uuids.len()).finish_non_exhaustive()
    }
}

/// Adapter names and descriptions that are never physical NICs (matched case-insensitively).
const VIRTUAL_NIC_PATTERNS: &[&str] = &[
    "hyper-v", "vethernet", "vmware", "vmnet", "virtualbox", "vbox", "docker", "wsl", "tap-", "tap0", "tap ", "tun", "wintun", "wireguard",
    "openvpn", "vpn", "bluetooth", "bnep", "loopback", "pseudo", "npcap", "zerotier", "tailscale", "veth", "virbr", "br-", "bridge", "utun",
    "awdl", "llw", "anpi", "parallels", "virtio", "kvm", "qemu", "teredo", "isatap", "6to4", "wan miniport", "microsoft kernel debug",
    "fortinet", "cisco anyconnect", "globalprotect", "nordlynx", "proton",
];

fn usable_mac(m: &[u8; 6]) -> bool {
    !mac_is_locally_administered(m) && m[0] & 0x01 == 0 && m.iter().any(|b| *b != 0) && m.iter().any(|b| *b != 0xff)
}

/// Keep globally administered physical NICs only (node-protocol section 4), deduplicated by MAC.
pub fn filter_nics(raw: &[RawNic]) -> Vec<HwNic> {
    let mut out: Vec<HwNic> = Vec::new();
    for n in raw {
        if n.virtual_ || !n.hardware || matches!(n.medium, Medium::Bluetooth | Medium::Loopback | Medium::Tunnel) {
            continue;
        }
        let label = format!("{} {}", n.name, n.description).to_lowercase();
        if VIRTUAL_NIC_PATTERNS.iter().any(|p| label.contains(p)) {
            continue;
        }
        // prefer the burned-in address; a randomized current address (private Wi-Fi address) is never sent
        let (mac, permanent) = match (n.permanent_mac.filter(usable_mac), n.mac.filter(usable_mac)) {
            (Some(p), _) => (p, true),
            (None, Some(m)) => (m, false),
            (None, None) => continue,
        };
        if out.iter().any(|o| o.mac == mac) {
            continue;
        }
        let kind = match n.medium {
            Medium::Ethernet => "ethernet",
            Medium::Wifi => "wifi",
            _ => "other",
        };
        out.push(HwNic { mac, kind: kind.into(), permanent, mac_display: mac_display(&mac) });
    }
    out
}

/// Placeholder serials and UUIDs firmware vendors leave in SMBIOS; the server ignores them, so they are never sent.
pub fn clean_identifier(v: Option<&str>) -> Option<String> {
    let v = v?.trim().trim_matches(char::from(0)).trim();
    if v.len() < 3 {
        return None;
    }
    let lower = v.to_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "to be filled", "default string", "not specified", "not applicable", "not available", "system serial number",
        "chassis serial number", "base board serial number", "baseboard serial number", "serial number", "none", "n/a", "na",
        "oem", "o.e.m", "0123456789", "123456789", "1234567890", "invalid", "unknown", "empty", "null", "xxxxxxxx",
        "03000200-0400-0500-0006-000700080009", "default", "type1productconfigid",
    ];
    if PLACEHOLDERS.iter().any(|p| lower == *p || (p.len() > 6 && lower.contains(p))) {
        return None;
    }
    let significant: Vec<char> = lower.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if significant.is_empty() || significant.iter().all(|c| *c == significant[0]) {
        return None; // all zeros, all F, all X, dashes and dots only
    }
    Some(v.to_string())
}

/// VM indicators from the platform's SMBIOS manufacturer and model, plus container / WSL hints.
pub fn vm_indicators(raw: &RawHw) -> Vec<String> {
    let text = format!("{} {}", raw.manufacturer.as_deref().unwrap_or(""), raw.model.as_deref().unwrap_or("")).to_lowercase();
    let mut v: Vec<String> = [
        ("vmware", "vmware"),
        ("virtualbox", "virtualbox"),
        ("innotek", "virtualbox"),
        ("virtual machine", "hyper-v"),
        ("hyper-v", "hyper-v"),
        ("kvm", "kvm"),
        ("qemu", "qemu"),
        ("xen", "xen"),
        ("parallels", "parallels"),
        ("virtualmac", "apple-virtualization"),
        ("bochs", "bochs"),
        ("amazon ec2", "cloud-vm"),
        ("google compute engine", "cloud-vm"),
    ]
    .iter()
    .filter(|(needle, _)| text.contains(needle))
    .map(|(_, tag)| tag.to_string())
    .collect();
    if raw.container {
        v.push("container".into());
    }
    if raw.wsl {
        v.push("wsl".into());
    }
    v.sort();
    v.dedup();
    v
}

/// Build the claims from raw readings (filters applied).
pub fn build(raw: &RawHw, device_id: &str, ek_pub_sha256: Option<[u8; 32]>, ts: u64) -> HwIdentifiers {
    let mut gpus: Vec<String> = raw.gpu_uuids.iter().filter_map(|g| clean_identifier(Some(g))).collect();
    gpus.sort();
    gpus.dedup();
    HwIdentifiers {
        device_id: device_id.to_string(),
        ts,
        ek_pub_sha256,
        gpu_uuids: gpus,
        smbios_uuid: clean_identifier(raw.smbios_uuid.as_deref()),
        board_serial: clean_identifier(raw.board_serial.as_deref()),
        disk_serial: clean_identifier(raw.disk_serial.as_deref()),
        os_install_id: clean_identifier(raw.os_install_id.as_deref()),
        nics: filter_nics(&raw.nics),
        vm_indicators: vm_indicators(raw),
    }
}

/// Sign with the device key: base64 COSE_Sign1 for `hw_ids`.
pub fn sign(ids: &HwIdentifiers, key: &dyn pool_proto::cose::Es256Signer) -> anyhow::Result<String> {
    let cose = pool_proto::cose::sign1(&ids.to_value(), key).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(pool_proto::keys::b64(&cose))
}

/// Reads the raw identifiers (the OS collector in the agent; a fixture in tests).
pub type Collector = Arc<dyn Fn() -> RawHw + Send + Sync>;

pub fn os_collector() -> Collector {
    Arc::new(collect)
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let v = hex::decode(hex).ok()?;
    v.try_into().ok()
}

/// Read the raw identifiers from this OS.
pub fn collect() -> RawHw {
    let mut raw = os::collect();
    raw.gpu_uuids = gpu_uuids();
    raw
}

#[cfg(feature = "nvml")]
fn gpu_uuids() -> Vec<String> {
    let Ok(n) = nvml_wrapper::Nvml::init() else { return vec![] };
    let count = n.device_count().unwrap_or(0);
    (0..count).filter_map(|i| n.device_by_index(i).ok()?.uuid().ok()).collect()
}

#[cfg(not(feature = "nvml"))]
fn gpu_uuids() -> Vec<String> {
    vec![]
}

#[cfg(windows)]
mod os {
    use super::{parse_mac, Medium, RawHw, RawNic};

    /// One PowerShell (CIM + NetAdapter) call; standard-user rights are enough. Output stays in memory.
    const SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$o.uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
$o.board=(Get-CimInstance Win32_BaseBoard).SerialNumber
$cs=Get-CimInstance Win32_ComputerSystem
$o.manufacturer=$cs.Manufacturer
$o.model=$cs.Model
$o.disk=(Get-CimInstance Win32_DiskDrive | Sort-Object Index | Select-Object -First 1).SerialNumber
$o.install=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$o.nics=@(Get-NetAdapter -IncludeHidden | ForEach-Object { [ordered]@{name=[string]$_.Name; desc=[string]$_.InterfaceDescription; mac=[string]$_.MacAddress; perm=[string]$_.PermanentAddress; virtual=[bool]$_.Virtual; hw=[bool]$_.HardwareInterface; medium=[int]$_.NdisPhysicalMedium} })
$o | ConvertTo-Json -Compress -Depth 4"#;

    pub fn collect() -> RawHw {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SCRIPT])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        let Ok(out) = out else {
            tracing::warn!("hardware identifiers: PowerShell unavailable");
            return RawHw::default();
        };
        parse(&String::from_utf8_lossy(&out.stdout))
    }

    pub fn parse(json: &str) -> RawHw {
        let v: serde_json::Value = serde_json::from_str(json.trim()).unwrap_or_default();
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let nics = match v.get("nics") {
            Some(serde_json::Value::Array(a)) => a.clone(),
            Some(o @ serde_json::Value::Object(_)) => vec![o.clone()],
            _ => vec![],
        };
        RawHw {
            smbios_uuid: s("uuid"),
            board_serial: s("board"),
            disk_serial: s("disk"),
            os_install_id: s("install"),
            manufacturer: s("manufacturer"),
            model: s("model"),
            nics: nics
                .iter()
                .map(|n| {
                    let t = |k: &str| n.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                    // NDIS_PHYSICAL_MEDIUM: 1 / 9 wireless LAN, 10 Bluetooth, 14 802.3
                    let medium = match n.get("medium").and_then(|x| x.as_i64()).unwrap_or(0) {
                        1 | 9 => Medium::Wifi,
                        10 => Medium::Bluetooth,
                        14 => Medium::Ethernet,
                        _ => Medium::Other,
                    };
                    RawNic {
                        name: t("name"),
                        description: t("desc"),
                        mac: parse_mac(&t("mac")),
                        permanent_mac: parse_mac(&t("perm")),
                        medium,
                        virtual_: n.get("virtual").and_then(|x| x.as_bool()).unwrap_or(false),
                        hardware: n.get("hw").and_then(|x| x.as_bool()).unwrap_or(true),
                    }
                })
                .collect(),
            ..Default::default()
        }
    }
}

#[cfg(target_os = "linux")]
mod os {
    use super::{parse_mac, Medium, RawHw, RawNic};
    use std::path::Path;

    fn read(p: impl AsRef<Path>) -> Option<String> {
        std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }

    pub fn collect() -> RawHw {
        let mut nics = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let dir = e.path();
                let real = std::fs::canonicalize(&dir).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let mac = read(dir.join("address")).and_then(|m| parse_mac(&m));
                let permanent = read(dir.join("addr_assign_type")).as_deref() == Some("0");
                let medium = if name == "lo" {
                    Medium::Loopback
                } else if dir.join("wireless").exists() || dir.join("phy80211").exists() {
                    Medium::Wifi
                } else if name.starts_with("bnep") || name.starts_with("bt") {
                    Medium::Bluetooth
                } else if read(dir.join("type")).as_deref() == Some("1") {
                    Medium::Ethernet
                } else if dir.join("tun_flags").exists() {
                    Medium::Tunnel
                } else {
                    Medium::Other
                };
                nics.push(RawNic {
                    name,
                    description: String::new(),
                    mac,
                    permanent_mac: if permanent { mac } else { None },
                    medium,
                    virtual_: real.contains("/devices/virtual/"),
                    hardware: dir.join("device").exists(),
                });
            }
        }
        let disk = ["nvme0n1", "sda", "vda", "mmcblk0"].iter().find_map(|d| {
            read(format!("/sys/block/{d}/device/serial")).or_else(|| {
                let b = std::fs::read(format!("/sys/block/{d}/device/vpd_pg80")).ok()?;
                b.get(4..).map(|s| String::from_utf8_lossy(s).trim().to_string()).filter(|s| !s.is_empty())
            })
        });
        let cgroup = read("/proc/1/cgroup").unwrap_or_default();
        RawHw {
            smbios_uuid: read("/sys/class/dmi/id/product_uuid"),
            board_serial: read("/sys/class/dmi/id/board_serial"),
            disk_serial: disk,
            os_install_id: read("/etc/machine-id"),
            manufacturer: read("/sys/class/dmi/id/sys_vendor"),
            model: read("/sys/class/dmi/id/product_name"),
            nics,
            container: Path::new("/.dockerenv").exists() || ["docker", "containerd", "kubepods", "lxc"].iter().any(|c| cgroup.contains(c)),
            wsl: read("/proc/sys/kernel/osrelease").map(|r| r.to_lowercase().contains("microsoft")).unwrap_or(false),
            ..Default::default()
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    use super::{parse_mac, Medium, RawHw, RawNic};

    fn run(cmd: &str, args: &[&str]) -> String {
        std::process::Command::new(cmd).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
    }

    fn ioreg_value(text: &str, key: &str) -> Option<String> {
        let line = text.lines().find(|l| l.contains(&format!("\"{key}\"")))?;
        let v = line.split('=').nth(1)?.trim();
        Some(v.trim_matches(|c| c == '"' || c == '<' || c == '>').to_string())
    }

    pub fn collect() -> RawHw {
        let pe = run("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
        let mut nics = Vec::new();
        let ports = run("/usr/sbin/networksetup", &["-listallhardwareports"]);
        for block in ports.split("\n\n") {
            let field = |k: &str| block.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
            let (Some(port), Some(dev)) = (field("Hardware Port:"), field("Device:")) else { continue };
            let mac = field("Ethernet Address:").and_then(|m| parse_mac(&m));
            let lower = port.to_lowercase();
            let medium = if lower.contains("wi-fi") || lower.contains("airport") {
                Medium::Wifi
            } else if lower.contains("bluetooth") {
                Medium::Bluetooth
            } else if lower.contains("ethernet") || lower.contains("lan") {
                Medium::Ethernet
            } else {
                Medium::Other
            };
            // networksetup lists the hardware (burned-in) address of each port
            nics.push(RawNic { name: dev, description: port, mac, permanent_mac: mac, medium, virtual_: false, hardware: true });
        }
        RawHw {
            smbios_uuid: ioreg_value(&pe, "IOPlatformUUID"),
            board_serial: ioreg_value(&pe, "IOPlatformSerialNumber"),
            manufacturer: ioreg_value(&pe, "manufacturer"),
            model: ioreg_value(&pe, "model"),
            nics,
            ..Default::default()
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod os {
    pub fn collect() -> super::RawHw {
        super::RawHw::default()
    }
}

/// No crash dump of the agent may carry raw identifiers or job data: Windows reports leave the heap out
/// (`WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`) and show no fault dialog; Unix disables core dumps.
pub fn disable_crash_dumps() {
    #[cfg(windows)]
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetErrorMode(mode: u32) -> u32;
            fn WerSetFlags(flags: u32) -> i32;
        }
        const SEM_FAILCRITICALERRORS: u32 = 0x0001;
        const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
        const WER_FAULT_REPORTING_FLAG_NOHEAP: u32 = 1;
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
    }
    #[cfg(unix)]
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-identical to the server's `fixtures/consent_texts.json` (`hw_identifiers`, draft-2), or the server answers
    /// 422 "Unknown consent text version".
    #[test]
    fn consent_text_matches_vaults_registry() {
        assert_eq!(CONSENT_VERSION, "2026-11-19.draft-2");
        assert_eq!(consent_text_sha256(), "348b878867d1d393e88393afca63c6227ed1446bf7fbd7f71858062c8ad19f3e");
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vault/fixtures/consent_texts.json");
        if let Ok(b) = std::fs::read(&fixture) {
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            let hw = v["texts"].as_array().unwrap().iter().find(|t| t["kind"] == "hw_identifiers").unwrap();
            assert_eq!(hw["version"], CONSENT_VERSION);
            assert_eq!(hw["text"], CONSENT_TEXT);
            assert_eq!(hw["text_sha256"], consent_text_sha256());
        }
    }

    fn nic(name: &str, desc: &str, mac: &str, perm: &str, medium: Medium, virtual_: bool, hardware: bool) -> RawNic {
        RawNic { name: name.into(), description: desc.into(), mac: parse_mac(mac), permanent_mac: parse_mac(perm), medium, virtual_, hardware }
    }

    /// Fixture adapter lists (as Windows `Get-NetAdapter`, Linux sysfs and macOS `networksetup` report them).
    #[test]
    fn nic_filters_keep_physical_globally_administered_adapters_only() {
        let windows = vec![
            nic("Ethernet", "Intel(R) Ethernet Connection (17) I219-V", "00-1B-21-AA-3F-9A", "001B21AA3F9A", Medium::Ethernet, false, true),
            // private (randomized) Wi-Fi address: the burned-in address is sent instead, marked permanent
            nic("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz", "3A-11-22-33-44-55", "8C-17-59-12-34-56", Medium::Wifi, false, true),
            nic("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", "00-15-5D-01-02-03", "", Medium::Ethernet, true, false),
            nic("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter #2", "00-15-5D-04-05-06", "", Medium::Ethernet, false, true),
            nic("VMware Network Adapter VMnet8", "VMware Virtual Ethernet Adapter for VMnet8", "00-50-56-C0-00-08", "", Medium::Ethernet, false, true),
            nic("Ethernet 3", "VirtualBox Host-Only Ethernet Adapter", "0A-00-27-00-00-0E", "", Medium::Ethernet, false, true),
            nic("OpenVPN TAP-Windows6", "TAP-Windows Adapter V9", "00-FF-AB-CD-EF-01", "", Medium::Ethernet, false, true),
            nic("Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)", "8C-17-59-12-34-57", "8C1759123457", Medium::Bluetooth, false, true),
            nic("Local Area Connection* 1", "Microsoft Wi-Fi Direct Virtual Adapter", "8E-17-59-12-34-56", "", Medium::Wifi, true, false),
            // a randomized address with no burned-in address known: dropped
            nic("Wi-Fi 2", "Realtek USB Wireless", "DA-A1-19-00-00-01", "", Medium::Wifi, false, true),
        ];
        let got = filter_nics(&windows);
        let macs: Vec<_> = got.iter().map(|n| (n.mac_display.as_str(), n.kind.as_str(), n.permanent)).collect();
        assert_eq!(macs, [("**:**:**:**:3f:9a", "ethernet", true), ("**:**:**:**:34:56", "wifi", true)]);

        let linux = vec![
            nic("lo", "", "00:00:00:00:00:00", "", Medium::Loopback, true, false),
            nic("enp3s0", "", "a8:a1:59:00:11:22", "a8:a1:59:00:11:22", Medium::Ethernet, false, true),
            nic("docker0", "", "02:42:ac:11:00:01", "", Medium::Ethernet, true, false),
            nic("br-5f2c", "", "02:42:1d:00:00:02", "", Medium::Ethernet, true, false),
            nic("veth12ab", "", "6e:01:02:03:04:05", "", Medium::Ethernet, true, false),
            nic("tun0", "", "", "", Medium::Tunnel, true, false),
            nic("wg0", "wireguard", "", "", Medium::Other, true, false),
            nic("virbr0", "", "52:54:00:12:34:56", "", Medium::Ethernet, true, false),
            nic("wlp2s0", "", "f4:4e:e3:aa:bb:cc", "", Medium::Wifi, false, true),
            // same physical NIC listed twice
            nic("enp3s0.10", "", "a8:a1:59:00:11:22", "", Medium::Ethernet, false, true),
        ];
        let got: Vec<_> = filter_nics(&linux).into_iter().map(|n| (n.mac_display, n.permanent)).collect();
        assert_eq!(got, [("**:**:**:**:11:22".to_string(), true), ("**:**:**:**:bb:cc".to_string(), false)]);

        let macos = vec![
            nic("en0", "Wi-Fi", "14:7d:da:01:02:03", "14:7d:da:01:02:03", Medium::Wifi, false, true),
            nic("en5", "Bluetooth PAN", "14:7d:da:01:02:04", "14:7d:da:01:02:04", Medium::Bluetooth, false, true),
            nic("bridge0", "Thunderbolt Bridge", "36:00:1f:00:00:01", "36:00:1f:00:00:01", Medium::Other, false, true),
        ];
        assert_eq!(filter_nics(&macos).len(), 1);
    }

    #[test]
    fn placeholder_serials_are_dropped() {
        for p in [
            "To be filled by O.E.M.", "Default string", "None", "0", "00000000", "0000000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "00000000-0000-0000-0000-000000000000", "03000200-0400-0500-0006-000700080009", "System Serial Number", "Not Specified", "N/A",
            "   ", "XXXXXXXXXX", "123456789", "Base Board Serial Number", "..........",
        ] {
            assert_eq!(clean_identifier(Some(p)), None, "{p:?}");
        }
        for ok in ["PF3ABCDE", "S4EWNX0R123456", "4C4C4544-0039-4810-8052-B4C04F4A3533", "/7XJ2KL3/CNWS2001234567/"] {
            assert_eq!(clean_identifier(Some(ok)).as_deref(), Some(ok));
        }
        assert_eq!(clean_identifier(Some("  S4EWNX0R123456  ")).as_deref(), Some("S4EWNX0R123456"));
        assert_eq!(clean_identifier(None), None);
    }

    #[test]
    fn vm_indicators_and_build() {
        let raw = RawHw {
            smbios_uuid: Some("To be filled by O.E.M.".into()),
            board_serial: Some("BOARD-1234".into()),
            disk_serial: Some("0000000000".into()),
            os_install_id: Some("1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e".into()),
            manufacturer: Some("VMware, Inc.".into()),
            model: Some("VMware20,1".into()),
            gpu_uuids: vec!["GPU-6b2f-aaaa".into(), "GPU-6b2f-aaaa".into(), "0".into()],
            nics: vec![],
            container: true,
            wsl: false,
        };
        let h = build(&raw, "0b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e", Some([1; 32]), 5);
        assert_eq!(h.smbios_uuid, None);
        assert_eq!(h.disk_serial, None);
        assert_eq!(h.board_serial.as_deref(), Some("BOARD-1234"));
        assert_eq!(h.gpu_uuids, ["GPU-6b2f-aaaa"]);
        assert_eq!(h.vm_indicators, ["container", "vmware"]);
        let physical = RawHw { manufacturer: Some("Dell Inc.".into()), model: Some("XPS 15 9530".into()), ..Default::default() };
        assert!(vm_indicators(&physical).is_empty());
        let hv = RawHw { manufacturer: Some("Microsoft Corporation".into()), model: Some("Virtual Machine".into()), ..Default::default() };
        assert_eq!(vm_indicators(&hv), ["hyper-v"]);
        // Debug of the raw readings never prints a value
        assert!(!format!("{raw:?}").contains("BOARD-1234"));
    }

    #[test]
    fn weekly_report_schedule() {
        let now = 100 * REPORT_INTERVAL_MS;
        assert!(!report_due(false, true, None, None, now), "never without consent");
        assert!(!report_due(true, false, None, None, now), "never before enrollment");
        assert!(report_due(true, true, None, None, now));
        assert!(!report_due(true, true, Some(now - REPORT_INTERVAL_MS + 1), None, now));
        assert!(report_due(true, true, Some(now - REPORT_INTERVAL_MS), None, now));
        assert!(!report_due(true, true, Some(now - 2 * REPORT_INTERVAL_MS), Some(now - 60_000), now), "failed attempt: wait an hour");
        assert_eq!(consent_text_sha256().len(), 64);
    }

    #[cfg(windows)]
    #[test]
    fn windows_netadapter_json_parses() {
        let json = r#"{"uuid":"4C4C4544-0039-4810-8052-B4C04F4A3533","board":"/7XJ2KL3/CN1/","manufacturer":"Dell Inc.","model":"XPS","disk":"S4EW","install":"1b0e8f0e-5c3a-4b52-9b8e-1f2a3b4c5d6e","nics":{"name":"Ethernet","desc":"Intel","mac":"00-1B-21-AA-3F-9A","perm":"001B21AA3F9A","virtual":false,"hw":true,"medium":14}}"#;
        let r = os::parse(json);
        assert_eq!(r.nics.len(), 1);
        assert_eq!(r.nics[0].medium, Medium::Ethernet);
        assert_eq!(filter_nics(&r.nics)[0].mac_display, "**:**:**:**:3f:9a");
        assert_eq!(r.disk_serial.as_deref(), Some("S4EW"));
    }
}
