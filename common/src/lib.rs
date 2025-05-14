use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{
    cmp::{max, min},
    num::ParseIntError,
};

/// Represents the complete input data structure for SBI calls
/// Contains both metadata and arguments
#[derive(Serialize, Deserialize)]
pub struct InputData {
    pub metadata: Metadata,
    pub args: Args,
}

/// Metadata information about the SBI call
#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub extension_name: String, // Name of the SBI extension
    pub source: String,         // Source of the input (e.g., generated, manual)
}

/// Arguments for an SBI call
/// All fields are serialized/deserialized as hexadecimal strings
#[derive(Serialize, Deserialize)]
pub struct Args {
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub eid: u64, // Extension ID
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub fid: u64, // Function ID
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg0: u64, // First argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg1: u64, // Second argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg2: u64, // Third argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg3: u64, // Fourth argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg4: u64, // Fifth argument
    #[serde(
        serialize_with = "serialize_to_hex",
        deserialize_with = "deserialize_from_hex"
    )]
    pub arg5: u64, // Sixth argument
}

impl InputData {
    /// Generate a short hash string for the input data
    /// Used for uniquely identifying inputs
    pub fn hash_string(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input_to_binary(self));
        let result = hasher.finalize();
        // Take first 4 bytes of the hash and convert to hex string
        result
            .iter()
            .take(4)
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>()
    }
}

/// Custom serializer to convert u64 values to hexadecimal strings
fn serialize_to_hex<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{:X}", value);
    serializer.serialize_str(&hex_string)
}

/// Custom deserializer to convert hexadecimal strings to u64 values
fn deserialize_from_hex<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(deserializer)?;
    let cleaned_str = hex_str.trim_start_matches("0x");
    u64::from_str_radix(cleaned_str, 16)
        .map_err(|e: ParseIntError| serde::de::Error::custom(format!("fail to parse int: {}", e)))
}

/// Parse TOML content into InputData structure
/// Handles conversion of hex literals in TOML to proper format
pub fn input_from_toml(toml_content: &str) -> InputData {
    // Fix hex literals in TOML by adding quotes around them
    let re = regex::Regex::new(r#"(=\s*)(0x[0-9A-Fa-f]+)"#).expect("compile regex");
    let toml_content = re.replace_all(&toml_content, r#"$1"$2""#).to_string();
    toml::from_str(&toml_content).expect("parse toml")
}

/// Size of binary input representation in bytes
pub const INPUT_SIZE: usize = 64;

/// Convert binary content to InputData structure
pub fn input_from_binary(binary_content: &[u8]) -> InputData {
    let mut binary_content = binary_content.to_vec();
    // Ensure the binary content is exactly INPUT_SIZE bytes
    binary_content.resize(INPUT_SIZE, 0);

    // Parse binary content into Args structure
    let args = Args {
        eid: u64::from_le_bytes(binary_content[0..8].try_into().unwrap()),
        fid: u64::from_le_bytes(binary_content[8..16].try_into().unwrap()),
        arg0: u64::from_le_bytes(binary_content[16..24].try_into().unwrap()),
        arg1: u64::from_le_bytes(binary_content[24..32].try_into().unwrap()),
        arg2: u64::from_le_bytes(binary_content[32..40].try_into().unwrap()),
        arg3: u64::from_le_bytes(binary_content[40..48].try_into().unwrap()),
        arg4: u64::from_le_bytes(binary_content[48..56].try_into().unwrap()),
        arg5: u64::from_le_bytes(binary_content[56..64].try_into().unwrap()),
    };

    // Create InputData with metadata
    InputData {
        metadata: Metadata {
            extension_name: get_extension_name(args.eid),
            source: String::new(),
        },
        args,
    }
}

/// Convert InputData to TOML format
pub fn input_to_toml(input: &InputData) -> String {
    let toml_content = toml::to_string_pretty(&input).expect("serialize toml");
    // Remove quotes around hex literals for better readability
    let re = regex::Regex::new(r#""(0x[0-9A-Fa-f]+)""#).expect("compile regex");
    re.replace_all(&toml_content, "$1").to_string()
}

/// Convert InputData to binary format
pub fn input_to_binary(input: &InputData) -> Vec<u8> {
    let mut binary_content = Vec::new();
    // Serialize all fields in little-endian byte order
    binary_content.extend_from_slice(&input.args.eid.to_le_bytes());
    binary_content.extend_from_slice(&input.args.fid.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg0.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg1.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg2.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg3.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg4.to_le_bytes());
    binary_content.extend_from_slice(&input.args.arg5.to_le_bytes());
    binary_content
}

/// Check if an SBI call would cause the system to halt
pub fn is_halt_sbi_call(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x8); // legacy shutdown
    res = res || (eid == 0x53525354 && fid == 0); // system reset
    res = res || (eid == 0x48534D && fid == 0x1); // hart stop
    res = res || (eid == 0x48534D && fid == 0x3); // hart suspend
    res
}

/// Get the extension name based on the extension ID (eid)
pub fn get_extension_name(eid: u64) -> String {
    match eid {
        0x0..=0xF_u64 => "legacy-".to_string() + eid.to_string().as_str(),
        0x10 => "base".to_string(),
        0x54494D45 => "timer".to_string(),
        0x735049 => "ipi".to_string(),
        0x52464E43 => "fence".to_string(),
        0x48534D => "hsm".to_string(),
        0x53525354 => "reset".to_string(),
        0x504D55 => "pmu".to_string(),
        0x4442434E => "console".to_string(),
        0x53555350 => "suspend".to_string(),
        0x43505043 => "cppc".to_string(),
        0x4E41434C => "nacl".to_string(),
        0x535441 => "sta".to_string(),
        0x535345 => "sse".to_string(),
        0x46574654 => "fwft".to_string(),
        0x44425452 => "dbtr".to_string(),
        0x4D505859 => "mpxy".to_string(),
        _ => "unknown".to_string(),
    }
}

// Valid memory address range for the target system
const START_ADDRESS: u64 = 0x8000_0000;
const END_ADDRESS: u64 = 0x8fff_ffff;

/// Fix input arguments to ensure they are within valid ranges
/// This prevents crashes due to invalid memory accesses
pub fn fix_input_args(mut data: InputData) -> InputData {
    let eid = data.args.eid;
    let fid = data.args.fid;

    // Fix arguments for calls where arg0 is an address
    if is_arg0_addr(eid, fid) {
        data.args.arg0 = max(min(data.args.arg0, END_ADDRESS), START_ADDRESS);
    }

    // Fix arguments for remote fence operations
    if is_remote_fence(eid, fid) {
        data.args.arg0 = max(min(data.args.arg0, END_ADDRESS), START_ADDRESS); // *hart_mask
        data.args.arg1 = max(min(data.args.arg1, END_ADDRESS), START_ADDRESS); // start
        data.args.arg2 = min(data.args.arg2, END_ADDRESS - data.args.arg1); // size
    }

    // Fix arguments for SSE read/write operations
    if is_sse_read_write(eid, fid) {
        data.args.arg4 = 0; // addr_hi
        data.args.arg3 = max(min(data.args.arg3, END_ADDRESS), START_ADDRESS); // addr_lo
        data.args.arg2 = min(data.args.arg2, (END_ADDRESS - data.args.arg3) / 8); // attr_count
    }

    // Fix arguments for console write operations
    if is_console_write(eid, fid) {
        data.args.arg2 = 0; // addr_hi
        data.args.arg1 = max(min(data.args.arg1, END_ADDRESS), START_ADDRESS); // addr_lo
        data.args.arg0 = min(min(data.args.arg0, END_ADDRESS - data.args.arg1), 0x100); // nums_bytes
    }

    // Fix arguments for PMU event info operations
    if is_get_pmu_event_info(eid, fid) {
        data.args.arg0 = max(min(data.args.arg0, END_ADDRESS), START_ADDRESS); // addr_lo
        data.args.arg1 = 0; // addr_hi
        data.args.arg2 = min(
            100,
            min(data.args.arg2, (END_ADDRESS - data.args.arg0) / 16),
        ); // num_entries
    }
    data
}

/// Check if arg0 is an address for the given extension and function IDs
fn is_arg0_addr(eid: u64, _: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x4); // send ipi
    res = res || (eid == 0x5); // remote fence
    res
}

/// Check if the call is a remote fence operation
fn is_remote_fence(eid: u64, _: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x6); // remote fence vma
    res = res || (eid == 0x7); // remote fence vma with asid
    res
}

/// Check if the call is an SSE read or write operation
fn is_sse_read_write(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x535345 && fid == 0x0); // sse read
    res = res || (eid == 0x535345 && fid == 0x1); // sse write
    res
}

/// Check if the call is a console write operation
fn is_console_write(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x4442434E && fid == 0);
    res
}

/// Check if the call is a PMU event info operation
fn is_get_pmu_event_info(eid: u64, fid: u64) -> bool {
    let mut res = false;
    res = res || (eid == 0x504D55 && fid == 0x8);
    res
}

/// Parse a string as a u64, supporting both decimal and hexadecimal (0x prefix) formats
pub fn parse_u64(s: &str) -> Result<u64, String> {
    let res = if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| format!("invalid hexadecimal eid: {}", s))?
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid decimal eid: {}", s))?
    };
    Ok(res)
}
