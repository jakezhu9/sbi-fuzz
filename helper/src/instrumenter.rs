use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// Include the instrument patch content directly from the file
const INSTRUMENT_PATCH: &str = include_str!("./instrument.patch");

/// Instruments OpenSBI code with KASAN (Kernel Address Sanitizer) support
///
/// This function applies a patch to the OpenSBI source code to add KASAN instrumentation,
/// which helps detect memory errors during runtime.
///
/// # Arguments
///
/// * `path` - Path to the OpenSBI source code directory
///
/// # Panics
///
/// * If the provided path is not a directory
/// * If file operations or git commands fail
pub fn instrument_kasan(path: PathBuf) {
    // Verify that the path points to a directory
    if !path.is_dir() {
        panic!("The specified path is not a directory, expected OpenSBI source code");
    }

    // Create a temporary patch file in the target directory
    let temp_patch_path = path.join("temp_patch.patch");
    fs::write(&temp_patch_path, INSTRUMENT_PATCH).expect("write instrument patch");

    // Execute git apply command to apply the patch to the source code
    let output = Command::new("git")
        .current_dir(path)
        .args(["apply", "temp_patch.patch"])
        .stdout(Stdio::inherit()) // Forward stdout to the parent process
        .stderr(Stdio::inherit()) // Forward stderr to the parent process
        .output()
        .expect("execute git apply command");

    // Clean up by removing the temporary patch file
    fs::remove_file(&temp_patch_path).expect("remove temporary patch file");

    // Provide feedback based on the patch application result
    if output.status.success() {
        println!(
            "Successfully applied instrument patch. Run `make PLATFORM=generic LLVM=1` to build."
        );
    } else {
        println!(
            "Failed to apply instrument patch. Is the path a valid OpenSBI source code directory?"
        );
    }
}
