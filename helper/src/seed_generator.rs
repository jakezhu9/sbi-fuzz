use common::*;
use std::fs::{self, File, create_dir_all};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;
use walkdir::WalkDir;

// Clone a git repository to a temporary directory and return the path to it
fn clone_repository(url: &str) -> PathBuf {
    // Create a temporary directory that won't be automatically deleted
    let temp_dir = tempdir().expect("create temp directory");
    let temp_path = temp_dir.into_path();
    println!(
        "Cloning repository to temp directory: {} source: {}",
        temp_path.display(),
        url
    );

    // Execute git clone command with depth=1 to get only the latest commit
    let output = Command::new("git")
        .args(&["clone", "--depth=1", url])
        .arg(&temp_path)
        .output()
        .expect("execute git clone command");

    // Check if the command was successful
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        panic!("Failed to clone repository: {}", error);
    }

    temp_path
}

// Parse an AsciiDoc file to extract SBI function information
// Returns a vector of tuples containing (function_name, fid, eid)
fn extract_sbi_function_listing(file_path: &Path) -> Vec<(String, String, String)> {
    let mut content = String::new();
    let mut file = File::open(file_path).expect("open file");
    file.read_to_string(&mut content).expect("read file");
    let mut functions = Vec::new();
    let mut in_function_section = false;
    let mut in_table = false;
    let mut skip_header = true;

    // Parse the AsciiDoc file line by line
    for line in content.lines() {
        // Look for the function listing section
        if line.contains("=== Function Listing") {
            in_function_section = true;
            continue;
        }
        if !in_function_section {
            continue;
        }

        // Detect table boundaries
        if line.contains("|===") {
            if !in_table {
                in_table = true;
                continue;
            } else {
                break; // End of table reached
            }
        }

        if in_table {
            // Skip the header row of the table
            if skip_header {
                skip_header = false;
                continue;
            }

            // Split the line by '|' character and clean up the parts
            let parts: Vec<&str> = line
                .split('|')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();

            // Extract function name, FID, and EID from table columns
            if parts.len() >= 4 {
                let function_name = parts[0].to_string();
                let fid = parts[2].to_string();
                let eid = parts[3].to_string();

                // Only add valid entries to the result
                if !function_name.is_empty() && !fid.is_empty() && !eid.is_empty() {
                    functions.push((function_name, fid, eid));
                }
            }
        }
    }
    functions
}

// URL of the RISC-V SBI documentation repository
const SBI_DOC_REPO: &str = "https://github.com/riscv-non-isa/riscv-sbi-doc.git";

// Generate seed files for SBI fuzzing based on the official RISC-V SBI documentation
pub fn generate(output: String) {
    // Create output directory if it doesn't exist
    let output_dir = PathBuf::from(output);
    create_dir_all(&output_dir).expect("create output directory");

    // Clone the SBI documentation repository
    let repo_dir = clone_repository(SBI_DOC_REPO);
    let src_dir = repo_dir.join("src");
    let mut count = 0;

    // Process all AsciiDoc files in the repository
    for entry in WalkDir::new(&src_dir) {
        let entry = entry.expect("read directory entry");
        let path = entry.path();

        // Only process AsciiDoc files
        if path.extension().unwrap_or_default() != "adoc" {
            continue;
        }

        // Get the extension name from the file name
        let extension_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        // Extract SBI function information from the file
        let functions = extract_sbi_function_listing(path);

        // Generate a seed file for each function
        for (func_name, fid, eid) in functions {
            // Clean up function name by removing "sbi_" prefix if present
            let clean_func_name = if func_name.starts_with("sbi_") {
                &func_name[4..]
            } else {
                &func_name
            };

            // Create input data structure for the seed
            let data = InputData {
                metadata: Metadata {
                    extension_name: get_extension_name(parse_u64(&eid).expect("parse eid")),
                    source: format!("sbifuzz-generate-{}-{}", extension_name, clean_func_name),
                },
                args: Args {
                    eid: parse_u64(&eid).expect("parse eid"),
                    fid: parse_u64(&fid).expect("parse fid"),
                    arg0: 0,
                    arg1: 0,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                    arg5: 0,
                },
            };

            // Write the seed to a TOML file
            let toml_path = output_dir.join(format!("{}-{}.toml", extension_name, clean_func_name));
            fs::write(&toml_path, input_to_toml(&data))
                .expect(format!("write toml file: {:?}", &toml_path).as_str());
            count += 1;
        }
    }
    println!("Generated {} seed files", count);
}
