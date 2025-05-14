.PHONY: all prepare run clean

all: prepare run

prepare:
	@if [ ! -d "output" ]; then \
		echo "> Preparing environment..." && \
		mkdir -p output && \
		(cd ../.. && make) && \
		cargo install cargo-binutils && \
		git clone https://github.com/rustsbi/rustsbi.git output/rustsbi && \
		(cd output/rustsbi && git checkout eb5a100f81e96d6bde0ce7f6bee1969d60427d1a) && \
		(cd output/rustsbi && cargo xtask prototyper) && \
		cargo helper generate-seed output/seed && \
		echo "> Preparation completed"; \
	else \
		echo "> Output directory already exists, skipping preparation. If you want to rebuild, run 'make clean' first"; \
	fi

run:
	@echo "> Running fuzzer..."
	cargo fuzzer --target output/rustsbi/target/riscv64imac-unknown-none-elf/release/rustsbi-prototyper.bin \
	  --injector ../../injector/build/injector.elf --seed output/seed --output output/result

clean:
	@echo "> Cleaning up..."
	rm -rf output
	@echo "> Cleanup completed"
