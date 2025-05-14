all: compile

compile: fuzzer helper injector
	@echo ">>> All components built successfully"

fuzzer:
	@echo ">>> Building fuzzer package..."
	cargo build --package fuzzer --release
	@echo ">>> Fuzzer build completed"

helper:
	@echo ">>> Building helper package..."
	cargo build --package helper --release
	@echo ">>> Helper build completed"

injector:
	@echo ">>> Building injector..."
	cd injector && make PREFIX="==>"
	@echo ">>> Injector build completed"

clean: clean-cargo clean-injector
	@echo ">>> All clean operations completed"

clean-cargo:
	@echo ">>> Cleaning cargo build artifacts..."
	cargo clean
	@echo ">>> Cargo clean completed"

clean-injector:
	@echo ">>> Cleaning injector build artifacts..."
	cd injector && make PREFIX="==>" clean
	@echo ">>> Injector clean completed"

help:
	@echo "Available targets:"
	@echo "  all (default)  - Build all components"
	@echo "  compile        - Same as 'all'"
	@echo "  fuzzer         - Build only the fuzzer package"
	@echo "  helper         - Build only the helper package"
	@echo "  injector       - Build only the injector"
	@echo "  clean          - Clean all build artifacts"
	@echo "  clean-cargo    - Clean only cargo build artifacts"
	@echo "  clean-injector - Clean only injector build artifacts"
	@echo "  help           - Display this help message"

.PHONY: all compile fuzzer helper injector clean clean-cargo clean-injector help
