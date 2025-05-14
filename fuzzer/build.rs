use libafl_qemu_build::build_libafl_qemu;

/// Build script for the libafl-qemu crate
/// This script is responsible for building the libafl-qemu library and linking it with the fuzzer. 
fn main() {
    build_libafl_qemu();
}
