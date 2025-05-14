use chrono::Local;
use common::*;
use core::time::Duration;
use csv::Writer;
use libafl::{
    Error, HasNamedMetadata,
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{EventConfig, launcher::Launcher},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::{ClientStats, Monitor, UserStatsValue},
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    nonzero,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    AsSlice, ClientId,
    core_affinity::Cores,
    current_nanos, current_time, impl_serdeany,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    Emulator, QemuExitError, QemuExitReason, QemuShutdownCause, Regs,
    elf::EasyElf,
    executor::QemuExecutor,
    modules::{DrCovModule, edges::StdEdgeCoverageModuleBuilder, utils::filters::StdAddressFilter},
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use std::{
    cmp::{max, min},
    collections::HashMap,
    fs::{self, OpenOptions},
    path::PathBuf,
    process::{self},
};

// Define the memory range for firmware
const FIRMWARE_ADDR_START: u64 = 0x8000_0000;
const FIRMWARE_ADDR_END: u64 = 0x8020_0000;

/// Main fuzzing function that sets up and runs the fuzzer
///
/// # Arguments
///
/// * `target` - Path to the target firmware
/// * `injector` - Path to the injector binary
/// * `seed_dir` - Directory containing seed inputs
/// * `objective_dir` - Directory to store objective findings
/// * `cores` - CPU cores to use for fuzzing
/// * `timeout` - Maximum execution time for each test case
/// * `dr_cov` - Optional path for Dr. Coverage output
/// * `check_skip_fn` - Function to determine if certain inputs should be skipped
pub fn fuzz(
    target: PathBuf,
    injector: PathBuf,
    seed_dir: Option<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
    cores: &str,
    timeout: Duration,
    dr_cov: Option<PathBuf>,
    monitor_csv: Option<PathBuf>,
    check_skip_fn: impl Fn(&InputData) -> bool,
) -> Result<(), Error> {
    // Parse arguments and create necessary directories
    if !objective_dir.exists() {
        fs::create_dir(&objective_dir).expect("create objective directory");
    }
    let objective_raw_dir = objective_dir.join(".raw");
    if !objective_raw_dir.exists() {
        fs::create_dir(&objective_raw_dir).expect("create raw objective directory");
    }
    let cores = Cores::from_cmdline(cores).expect("parse cores");
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

    // Define the client function that will be executed for each fuzzing instance
    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
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
            "null",
            "-nographic",
            "-snapshot",
            "-no-shutdown",
            "-S",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

        // Set up observers for coverage and timing
        let time_observer = TimeObserver::new("time");
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Configure Dr. Coverage if provided
        let mut dr_cov_path = PathBuf::from("");
        let mut dr_cov_addr = 0..0;
        let mut dr_cov_module_map: RangeMap<u64, (u16, String)> = RangeMap::new();
        if dr_cov.is_some() {
            dr_cov_path = dr_cov.clone().unwrap();
            dr_cov_addr = FIRMWARE_ADDR_START..FIRMWARE_ADDR_END;
            dr_cov_module_map.insert(
                FIRMWARE_ADDR_START..FIRMWARE_ADDR_END,
                (1, "sbi".to_string()),
            );
        }

        // Set up coverage modules
        let emulator_modules = tuple_list!(
            StdEdgeCoverageModuleBuilder::default()
                .address_filter(StdAddressFilter::allow_list(vec![
                    FIRMWARE_ADDR_START..FIRMWARE_ADDR_END
                ]))
                .map_observer(edges_observer.as_mut())
                .build()
                .expect("build std edge coverage module"),
            DrCovModule::builder()
                .filename(dr_cov_path)
                .module_mapping(dr_cov_module_map)
                .filter(StdAddressFilter::allow_list(vec![dr_cov_addr]))
                .full_trace(false)
                .build()
        );

        // Initialize the QEMU emulator and set breakpoints
        let emulator = Emulator::empty()
            .qemu_parameters(qemu_config)
            .modules(emulator_modules)
            .build()?;
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

        // Save initial CPU state for restoring between runs
        let saved_cpu_state = qemu.cpu_from_index(0).save_state();
        let snap = qemu.create_fast_snapshot(true);

        // Define the execution harness function
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           state: &mut StdState<_, _, _, _>,
                           input: &BytesInput| {
            // Convert fuzzer input to fixed-size binary
            let target = input.target_bytes();
            let mut buf = vec![0; INPUT_SIZE];
            let copy_len = min(target.len(), INPUT_SIZE);
            buf[..copy_len].copy_from_slice(&(target.as_slice())[0..copy_len]);

            // Process and validate the input
            let input = input_from_binary(&buf);
            let mut input = fix_input_args(input);
            if check_skip_fn(&input) {
                // Skip execution if user-defined function says so
                return ExitKind::Ok;
            }
            let st = state
                .named_metadata::<ObjectiveCountMetadata>("objective_id_count")
                .expect("get count");
            if st.get_eid_count(input.args.eid) >= 100
                || st.get_count(input.args.eid, input.args.fid) >= 10
            {
                // Limit number of crashes per extension ID / function ID to avoid excessive findings
                return ExitKind::Ok;
            }

            let hash = input.hash_string();
            let toml_path = objective_dir.join(format!(
                "{}-{:x}-{}.toml",
                input.metadata.extension_name, input.args.fid, hash
            ));
            if toml_path.exists() {
                // Skip execution if input has already been recorded
                return ExitKind::Ok;
            }

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
                    qemu_ret = ExitKind::Crash;
                }
                // Verify return value is a standard SBI error code
                let a0 = cpu.read_reg(Regs::A0).unwrap_or(1);
                if !(-13..=0).contains(&(a0 as i64)) {
                    qemu_ret = ExitKind::Crash;
                }
            }
            // Special handling for SBI calls that may cause halts
            if qemu_ret == ExitKind::Timeout && is_halt_sbi_call(input.args.eid, input.args.fid) {
                qemu_ret = ExitKind::Ok
            }

            // Save interesting inputs that cause crashes or timeouts
            if qemu_ret != ExitKind::Ok {
                input.metadata.source = format!("fuzz-{}-{:?}", hash, qemu_ret);
                fs::write(&toml_path, input_to_toml(&input))
                    .expect(format!("write toml file: {:?}", &toml_path).as_str());
                state
                    .named_metadata_mut::<ObjectiveCountMetadata>("objective_id_count")
                    .expect("get count")
                    .add_count(input.args.eid, input.args.fid);
            }

            // Restore emulator state for next run
            unsafe { emulator.restore_fast_snapshot(snap) }
            emulator
                .qemu()
                .cpu_from_index(0)
                .restore_state(&saved_cpu_state);

            qemu_ret
        };

        // Set up feedback mechanisms for the fuzzer
        let mut feedback = feedback_or!(
            TimeFeedback::new(&time_observer),
            MaxMapFeedback::new(&edges_observer)
        );
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // Initialize or use provided fuzzer state
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryOnDiskCorpus::new(objective_dir.join(".corpus"))
                    .expect("create on disk corpus"),
                OnDiskCorpus::new(&objective_raw_dir).expect("create on disk corpus"),
                &mut feedback,
                &mut objective,
            )
            .expect("create state")
        });

        // Initialize objective count metadata
        let mut objective_id_count = ObjectiveCountMetadata::new();
        let output_paths = fs::read_dir(&objective_dir).expect("read output dir");
        for path in output_paths {
            let path = path.expect("read path").path();
            if path.extension().unwrap_or_default() != "toml" {
                continue;
            }
            let input = input_from_toml(&fs::read_to_string(&path).expect("read toml"));
            objective_id_count.add_count(input.args.eid, input.args.fid);
        }
        state.add_named_metadata("objective_id_count", objective_id_count);

        // Configure scheduler, fuzzer, and executor
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("create executor");

        // Configure execution behavior and load initial inputs
        executor.break_on_timeout();
        if state.must_load_initial_inputs() {
            match seed_dir.clone() {
                Some(dir) => {
                    state
                        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[dir])
                        .unwrap_or_else(|_| {
                            println!("Failed to load initial corpus at {:?}", &seed_dir);
                            process::exit(0);
                        });
                }
                None => {
                    let mut generator = RandBytesGenerator::new(nonzero!(INPUT_SIZE));
                    state
                        .generate_initial_inputs(
                            &mut fuzzer,
                            &mut executor,
                            &mut generator,
                            &mut mgr,
                            100,
                        )
                        .unwrap_or_else(|_| {
                            println!("Failed to generate initial corpus");
                            process::exit(0);
                        });
                }
            }
        }

        // Set up mutation strategy and start the fuzzing loop
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("fuzz loop");
        Ok(())
    };

    // Set up shared memory, monitoring, and launch the fuzzer
    let shmem_provider = StdShMemProvider::new().expect("init shared memory");
    let monitor = MultiMonitorWithCSV::new(monitor_csv);
    let mut launcher = Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .run_client(&mut run_client)
        .cores(&cores)
        .monitor(monitor)
        .build();

    // Start the fuzzing campaign
    launcher.launch()
}

/// Tracking monitor during fuzzing and display both per-client and cumulative info.
#[derive(Clone)]
pub struct MultiMonitorWithCSV {
    csv_path: Option<PathBuf>,
    start_time: Duration,
    last_display: Duration,
    last_client_id: ClientId,
    client_stats: Vec<ClientStats>,
}

impl MultiMonitorWithCSV {
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(csv_path: Option<PathBuf>) -> Self {
        if csv_path.is_some() {
            let csv_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(csv_path.clone().unwrap())
                .expect("open csv file");
            let mut writer = Writer::from_writer(csv_file);
            writer
                .write_record(&[
                    "ClientID",
                    "Time",
                    "Runtime",
                    "Clients",
                    "Corpus",
                    "Objective",
                    "Executions",
                    "Speed",
                    "Edges",
                ])
                .expect("write csv header");
            writer.flush().expect("flush csv");
        }
        Self {
            csv_path,
            start_time: current_time(),
            last_display: Duration::from_secs(0),
            last_client_id: ClientId(0),
            client_stats: vec![],
        }
    }

    /// Returns the number of edges found.
    fn count_edges_found(&self) -> usize {
        let mut count = 0;
        for i in 0..self.client_stats_count() {
            let client = self.client_stats_for(libafl_bolts::ClientId((i + 1) as _));
            client
                .user_monitor
                .get("edges")
                .map(|val| match val.value() {
                    UserStatsValue::Ratio(_, val) => count = max(count, *val as _),
                    _ => {}
                });
        }
        count
    }
}

impl Monitor for MultiMonitorWithCSV {
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    fn aggregate(&mut self, _: &str) {}

    /// Display the current status of the fuzzer
    fn display(&mut self, _: &str, client_id: ClientId) {
        let ct = current_time();
        if (ct - self.last_display < Duration::from_millis(100))
            && (client_id == self.last_client_id)
        {
            return;
        }
        self.last_display = ct;
        self.last_client_id = client_id;

        let now = Local::now();
        let formatted_time = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let runtime = format_duration_hmsf(&(ct - self.start_time));
        let clients = self.client_stats_count();
        let cropus = self.corpus_size();
        let objectives = self.objective_size();
        let executions = self.total_execs();
        let speed = self.execs_per_sec_pretty();
        let edges = self.count_edges_found();
        println!(
            "[{}] [FUZZER] Runtime: {} | Clients: {} | Corpus: {} | Objective: {} | Executions: {} | Speed: {} exec/sec | Edges: {}",
            formatted_time, runtime, clients, cropus, objectives, executions, speed, edges
        );

        if self.csv_path.is_some() {
            let csv_file = OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(self.csv_path.clone().unwrap())
                .expect("open csv file");
            let mut writer = Writer::from_writer(csv_file);
            writer
                .write_record(&[
                    "GLOBAL",
                    &formatted_time,
                    &runtime,
                    &clients.to_string(),
                    &cropus.to_string(),
                    &objectives.to_string(),
                    &executions.to_string(),
                    &format!("{:.2}", self.execs_per_sec()),
                    &edges.to_string(),
                ])
                .expect("write csv global data");
            let client = &mut self.client_stats_mut()[client_id.0 as usize];
            let edges = client
                .user_monitor
                .get("edges")
                .map(|val| match val.value() {
                    UserStatsValue::Ratio(_, val) => val.to_string(),
                    _ => "".to_string(),
                })
                .unwrap_or_default();
            writer
                .write_record(&[
                    &client_id.0.to_string(),
                    &formatted_time,
                    &format_duration_hmsf(&(ct - client.start_time)),
                    "",
                    &client.corpus_size.to_string(),
                    &client.objective_size.to_string(),
                    &client.executions.to_string(),
                    &format!("{:.2}", client.execs_per_sec(ct)),
                    &edges,
                ])
                .expect("write csv client data");
            writer.flush().expect("flush csv");
        }
    }
}

/// Formats a Duration into a human-readable string in the format "HH:MM:SS.mmm"
///
/// # Arguments
///
/// * `duration` - The Duration to format
///
/// # Returns
///
/// A string representation of the duration in hours, minutes, seconds, and milliseconds
fn format_duration_hmsf(duration: &Duration) -> String {
    // Convert total duration to milliseconds
    let total_ms = duration.as_millis();

    // Calculate hours component
    let hours = total_ms / (1000 * 60 * 60);

    // Calculate minutes component (modulo 60 to get only the minutes part)
    let minutes = (total_ms / (1000 * 60)) % 60;

    // Calculate seconds component (modulo 60 to get only the seconds part)
    let seconds = (total_ms / 1000) % 60;

    // Calculate milliseconds component
    let milliseconds = total_ms % 1000;

    // Format the components into a string with zero-padding
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        hours, minutes, seconds, milliseconds
    )
}

/// A structure to track and store counts of different SBI call objectives
/// Stores counts indexed by EID (extension ID) and EID-FID (extension ID - function ID) pairs
#[derive(Debug, Serialize, Deserialize)]
struct ObjectiveCountMetadata {
    // HashMap storing counts for each EID and EID-FID combination
    count: HashMap<String, u64>,
}

impl ObjectiveCountMetadata {
    /// Creates a new empty ObjectiveCountMetadata instance
    fn new() -> Self {
        Self {
            count: HashMap::new(),
        }
    }

    /// Increments the count for a specific EID and EID-FID combination
    ///
    /// # Arguments
    ///
    /// * `eid` - Extension ID
    /// * `fid` - Function ID
    fn add_count(&mut self, eid: u64, fid: u64) {
        // Increment count for the EID
        *self.count.entry(format!("{:x}", eid)).or_insert(0) += 1;

        // Increment count for the EID-FID combination
        *self
            .count
            .entry(format!("{:x}-{:x}", eid, fid))
            .or_insert(0) += 1;
    }

    /// Gets the count for a specific EID-FID combination
    ///
    /// # Arguments
    ///
    /// * `eid` - Extension ID
    /// * `fid` - Function ID
    ///
    /// # Returns
    ///
    /// The count for the specified EID-FID combination, or 0 if not found
    fn get_count(&self, eid: u64, fid: u64) -> u64 {
        *self
            .count
            .get(&format!("{:x}-{:x}", eid, fid))
            .unwrap_or(&0)
    }

    /// Gets the count for a specific EID across all function IDs
    ///
    /// # Arguments
    ///
    /// * `eid` - Extension ID
    ///
    /// # Returns
    ///
    /// The total count for the specified EID, or 0 if not found
    fn get_eid_count(&self, eid: u64) -> u64 {
        *self.count.get(&format!("{:x}", eid)).unwrap_or(&0)
    }
}

// Implement serialization/deserialization for the ObjectiveCountMetadata struct
impl_serdeany!(ObjectiveCountMetadata);
