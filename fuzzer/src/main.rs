use clap::Parser;
use common::*;
use libafl::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use walkdir::WalkDir;

mod fuzz;

/// Command line interface definition for the SBI firmware fuzzer
#[derive(Parser)]
#[clap(name = "fuzzer")]
#[clap(about = "A tool for fuzzing sbi firmware")]
struct Cli {
    /// Specify the target program (binary format, e.g. "fw_dynamic.bin")
    #[clap(short, long)]
    target: PathBuf,

    /// Specify the injector program (elf format)
    #[clap(short, long)]
    injector: PathBuf,

    /// Specify the output directory for objective results
    #[clap(short, long)]
    output: PathBuf,

    /// Specify the seeds directory. If not provided, the fuzzer will generate random seeds
    #[clap(short, long)]
    seed: Option<PathBuf>,

    /// Specify the port for communication between broker and clients
    #[clap(long, default_value = "1337")]
    broker_port: u16,

    /// CPU cores to use (e.g. "1,2-4,6", "all")
    #[clap(long, default_value = "1")]
    cores: String,

    /// Timeout for each execution in milliseconds
    #[clap(long, default_value = "100")]
    timeout: u64,

    /// Specify custom inputs to skip (eg. "1:2,3" inputs with eid=1, fid=2 and inputs with eid=3)
    #[clap(long, value_name = "EID[:FID]", value_delimiter = ',')]
    skip_inputs: Vec<SkipInput>,

    /// Enable drCovModule and output results to the specified file [default: disable]
    #[clap(long)]
    dr_cov: Option<PathBuf>,

    /// Enable CSV stats output to the specified file [default: disable]
    #[clap(long)]
    csv_stats: Option<PathBuf>,

    /// Enable skip inputs that cause system halt (e.g., shutdown) [default: disable]
    #[clap(long, action = clap::ArgAction::SetTrue)]
    skip_halt: bool,
}

/// Represents an input pattern to skip during fuzzing
/// Can be either a specific EID or an EID:FID pair
#[derive(Debug, Clone)]
struct SkipInput {
    eid: u64,
    fid: Option<u64>,
}

impl FromStr for SkipInput {
    type Err = String;

    /// Parse a string in the format "EID[:FID]" into a SkipInput
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            1 => {
                let eid = parse_u64(parts[0]).map_err(|_| format!("parse eid: {}", parts[0]))?;
                Ok(SkipInput { eid, fid: None })
            }
            2 => {
                let eid = parse_u64(parts[0]).map_err(|_| format!("parse eid: {}", parts[0]))?;
                let fid = if parts[1].is_empty() {
                    None
                } else {
                    Some(parse_u64(parts[1]).map_err(|_| format!("parse fid: {}", parts[1]))?)
                };

                Ok(SkipInput { eid, fid })
            }
            _ => Err(format!("invalid format: {}, expected format: EID[:FID]", s)),
        }
    }
}

/// Temporary directory to store binary seed files
const TEMP_SEED_DIR: &str = "/tmp/sbifuzz_seed";

/// Prepare seed files by converting TOML format to binary format
///
/// This function reads TOML files from the input directory, converts them
/// to binary format, and writes them to a temporary directory for the fuzzer
fn prepare_seeds(dir: &PathBuf) {
    let binary_seed_dir = Path::new(TEMP_SEED_DIR);
    // Clean up any existing temporary directory
    if binary_seed_dir.exists() {
        if binary_seed_dir.is_dir() {
            fs::remove_dir_all(binary_seed_dir).expect("remove temporary seed directory");
        } else {
            fs::remove_file(binary_seed_dir).expect("remove temporary seed file");
        }
    }
    fs::create_dir(&binary_seed_dir).expect("create temporary seed directory");

    // Process each TOML file in the input directory
    for entry in WalkDir::new(dir) {
        let entry = entry.unwrap();
        let entry_path = entry.path();
        let ext = entry_path.extension();
        if !entry_path.is_file() || ext.is_none() || ext.unwrap() != "toml" {
            continue;
        }

        // Convert TOML to binary format
        let toml_content = fs::read_to_string(entry_path).expect("read toml file");
        let toml_data = input_from_toml(&toml_content);
        let file_name = entry_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let output_file_path = binary_seed_dir.join(file_name);
        let mut output_file = File::create(&output_file_path).expect("create binary seed file");
        output_file
            .write_all(&input_to_binary(&toml_data))
            .expect("write binary seed file");
    }
}

/// Generate a function that determines whether to skip a particular input
///
/// # Arguments
///
/// * `skip_halt` - Whether to skip inputs that would cause system halt
/// * `skip_inputs` - List of specific inputs to skip
///
/// # Returns
///
/// A function that takes EID and FID and returns true if the input should be skipped
fn gen_skip_input_fn(skip_halt: bool, skip_inputs: &[SkipInput]) -> impl Fn(&InputData) -> bool {
    move |input| {
        let eid = input.args.eid;
        let fid = input.args.fid;

        // Skip shutdown calls as they will cause unexpected qemu exit
        if eid == 0x8 || (eid == 0x53525354 && fid == 0 && input.args.arg0 == 0) {
            return true;
        }

        // Skip system halt calls if requested
        if skip_halt && is_halt_sbi_call(eid, fid) {
            return true;
        }

        // Skip specifically listed inputs
        for skip_input in skip_inputs {
            if skip_input.eid == eid && (skip_input.fid.is_none() || skip_input.fid.unwrap() == fid)
            {
                return true;
            }
        }
        false
    }
}

fn main() {
    // Parse command line arguments
    let args = Cli::parse();

    // Convert seed files from TOML to binary format
    let mut seed_dir = None;
    if args.seed.is_some() {
        prepare_seeds(&args.seed.clone().unwrap());
        seed_dir = Some(PathBuf::from(TEMP_SEED_DIR));
    }

    // Start the fuzzing process
    let res = fuzz::fuzz(
        args.target,
        args.injector,
        seed_dir,
        args.output,
        args.broker_port,
        &args.cores,
        Duration::from_millis(args.timeout),
        args.dr_cov,
        args.csv_stats,
        gen_skip_input_fn(args.skip_halt, &args.skip_inputs),
    );

    // Handle the result
    match res {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
