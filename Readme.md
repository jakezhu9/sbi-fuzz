# sbi-fuzz - RISC-V SBI Firmware Fuzzing

sbifuzz is a fuzzing framework designed to test RISC-V SBI (Supervisor Binary Interface) implementations. It helps discover potential vulnerabilities and abnormal behaviors in SBI implementations.

## Project Structure

```
sbifuzz/
├── common/          # Common libraries and utility functions
├── fuzzer/          # Core fuzzing logic
├── helper/          # Helper tools (seed generation, runners, etc.)
├── injector/        # Injector implementations
├── playground/      # Examples and test cases
└── Dockerfile.dev   # Development environment Dockerfile
```

## Key Features

- 🚀 Full support for all SBI extensions
- 🎯 Smart coverage-guided fuzzing
- 🔥 No firmware source needed
- ⚡ Fast execution with snapshotting and parallelization
- 🛡️ Built-in sanitizer support
- 📚 SBI doc-driven seed generation

## Quick Start

To get started with fuzzing RustSBI:

```bash
cd playground/rustsbi-fuzz
make
```

## Usage

1. Build the project:
```bash
make
```

2. Generate seed input:
```bash
cargo helper generate-seed output/seed
```

3. Run fuzzing:
```bash
cargo fuzzer --target <firmware> --injector <injector> --seed output/seed --output output/result
```

## Examples

Example test cases for OpenSBI and RustSBI are provided in the `playground` directory.

## Development Environment

We provides a VSCode dev container configuration for easy setup. To use it, see https://aka.ms/vscode-remote/containers.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
