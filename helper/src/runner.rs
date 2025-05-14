use common::*;
use libafl::executors::ExitKind;
use libafl::{
    corpus::InMemoryCorpus,
    observers::{CanTrack, HitcountsMapObserver, VariableMapObserver},
    state::StdState,
};
use libafl_bolts::{ownedref::OwnedMutSlice, tuples::tuple_list};
use libafl_qemu::{
    Emulator, QemuExitError, QemuExitReason, QemuShutdownCause, Regs, elf::EasyElf,
    modules::edges::StdEdgeCoverageModuleBuilder,
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{
    fs::{self},
    path::PathBuf,
    process,
};

/// Execute a single test case in the QEMU emulator
///
/// This function loads the target firmware and injector into QEMU,
/// sets up breakpoints, and executes the provided input.
///
/// # Arguments
///
/// * `target` - Path to the SBI firmware binary
/// * `injector` - Path to the ELF injector program
/// * `input` - Path to the TOML input file to test
pub fn run(target: PathBuf, injector: PathBuf, input: PathBuf) {
    // Read ELF file from injector path
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(&injector, &mut elf_buffer).expect("load injector elf");

    // Resolve important symbols from the injector ELF file
    let input_addr = elf
        .resolve_symbol("FUZZ_INPUT", 0)
        .expect("symbol FUZZ_INPUT not found");
    let main_addr = elf
        .resolve_symbol("main", 0)
        .expect("symbol main not found");
    let breakpoint = elf
        .resolve_symbol("BREAKPOINT", 0)
        .expect("symbol BREAKPOINT not found");

    // Configure QEMU parameters
    let qemu_config = vec![
        "fuzzer",
        "-M",
        "virt",
        "-smp",
        "1",
        "-m",
        "256M",
        "-bios",
        target.clone().to_str().expect("target path"),
        "-kernel",
        injector.clone().to_str().expect("injector path"),
        "-monitor",
        "null",
        "-serial",
        "stdio",
        "-nographic",
        "-snapshot",
        //"-no-shutdown",
        "-S",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect::<Vec<String>>();

    // Set up observers for coverage and timing
    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    // Set up coverage modules
    let emulator_modules = tuple_list!(
        StdEdgeCoverageModuleBuilder::default()
            .map_observer(edges_observer.as_mut())
            .build()
            .expect("build std edge coverage module")
    );

    // Initialize the QEMU emulator and set breakpoints
    let emulator: Emulator<
        libafl_qemu::command::NopCommand,
        libafl_qemu::command::NopCommandManager,
        libafl_qemu::NopEmulatorDriver,
        (
            libafl_qemu::modules::EdgeCoverageModule<
                libafl_qemu::modules::utils::filters::StdAddressFilter,
                libafl_qemu::modules::utils::filters::StdPageFilter,
                libafl_qemu::modules::edges::EdgeCoverageFullVariant,
                false,
                0,
            >,
            (),
        ),
        libafl::inputs::ValueInput<Vec<u8>>,
        StdState<
            InMemoryCorpus<libafl::inputs::ValueInput<Vec<u8>>>,
            libafl::inputs::ValueInput<Vec<u8>>,
            libafl_bolts::rands::RomuDuoJrRand,
            libafl::corpus::ondisk::OnDiskCorpus<libafl::inputs::ValueInput<Vec<u8>>>,
        >,
        libafl_qemu::NopSnapshotManager,
    > = Emulator::empty()
        .qemu_parameters(qemu_config)
        .modules(emulator_modules)
        .build()
        .expect("build emulator");
    let qemu = emulator.qemu();
    qemu.set_breakpoint(main_addr);
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(_)) => {}
            _ => panic!("Unexpected QEMU exit."),
        }
    }
    qemu.remove_breakpoint(main_addr);
    qemu.set_breakpoint(breakpoint);

    // Process and validate the input
    let toml_content = fs::read_to_string(&input).expect("read input file");
    let input = input_from_toml(&toml_content);

    // Write input to emulator memory and execute
    unsafe { emulator.write_phys_mem(input_addr, &input_to_binary(&input)) }
    let mut qemu_ret = match unsafe { emulator.qemu().run() } {
        Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
        Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
        Err(QemuExitError::UnexpectedExit) => ExitKind::Crash,
        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
            // Handle external signals to stop fuzzing
            signal.handle();
            process::exit(0);
        }
        e => panic!("Unexpected QEMU exit: {e:?}."),
    };

    // Validate execution results
    if qemu_ret == ExitKind::Ok {
        // Verify we reached the expected breakpoint
        let cpu = emulator.qemu().cpu_from_index(0);
        let pc = cpu.read_reg(Regs::Pc).unwrap_or(0);
        if !(breakpoint..breakpoint + 5).contains(&pc) {
            println!(
                "Unexpected PC: {:#x}, expected breakpoint at {:#x}",
                pc, breakpoint
            );
            qemu_ret = ExitKind::Crash;
        }
        // Verify return value is a standard SBI error code
        let a0 = cpu.read_reg(Regs::A0).unwrap_or(1);
        if !(-13..=0).contains(&(a0 as i64)) {
            println!("Invalid return value: {:#x}, expected SBI error code", a0);
            qemu_ret = ExitKind::Crash;
        }
    }

    println!("Run finish. Exit kind: {:?}", qemu_ret);
}

const TEMP_INPUT_BINARY: &str = "/tmp/sbifuzz_input.bin";

/// Debug mode for interactive testing with GDB
///
/// This function prepares the input and starts QEMU in debug mode,
/// allowing a GDB instance to connect for interactive debugging.
///
/// # Arguments
///
/// * `target` - Path to the SBI firmware binary
/// * `injector` - Path to the ELF injector program
/// * `input` - Path to the TOML input file to debug
pub fn debug(target: PathBuf, injector: PathBuf, input: PathBuf) {
    // Read and convert the TOML input to binary format
    let toml_content = fs::read_to_string(&input).expect("read input file");
    let input = input_from_toml(&toml_content);
    let input_binary = input_to_binary(&input);

    // Write the binary input to a temporary file for GDB to load
    fs::write(TEMP_INPUT_BINARY, &input_binary).expect("write input binary");

    // Parse the injector ELF to get important symbol addresses for debugging
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(&injector, &mut elf_buffer).expect("load injector elf");
    let main_addr = elf
        .resolve_symbol("main", 0)
        .expect("symbol main not found");
    let input_addr = elf
        .resolve_symbol("FUZZ_INPUT", 0)
        .expect("symbol FUZZ_INPUT not found");
    let breakpoint = elf
        .resolve_symbol("BREAKPOINT", 0)
        .expect("symbol BREAKPOINT not found");

    // Prepare QEMU command line arguments for debug mode
    let args = vec![
        "qemu-system-riscv64",
        "-M",
        "virt",
        "-smp",
        "1",
        "-m",
        "256M",
        "-bios",
        target.to_str().expect("target path"),
        "-kernel",
        injector.to_str().expect("injector path"),
        "-monitor",
        "null",
        "-serial",
        "stdio",
        "-nographic",
        "-snapshot",
        "-no-shutdown",
        "-S",
        "-s",
    ];
    let program = &args[0];
    let program_args = &args[1..];
    let mut cmd = Command::new(program);
    cmd.args(program_args);

    // Print instructions for connecting GDB to the QEMU instance
    println!(
        r#"A QEMU will be started. You can run the following command to attach GDB:
gdb-multiarch -ex "target remote :1234" \
    -ex "restore {TEMP_INPUT_BINARY} binary 0x{:x}" -ex "b *0x{:x}" -ex "b *0x{:x}" # load input and set breakpoint"#,
        input_addr, main_addr, breakpoint
    );

    let err = cmd.exec();

    eprintln!("run failed: {}, command: {:?}", err, cmd);
    std::process::exit(1);
}
