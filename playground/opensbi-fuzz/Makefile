.PHONY: all prepare run clean

all: prepare run

prepare:
	@if [ ! -d "output" ]; then \
		echo "> Preparing environment..." && \
		mkdir -p output && \
		(cd ../.. && make) && \
		git clone https://github.com/riscv-software-src/opensbi.git output/opensbi && \
		(cd output/opensbi && git checkout v1.6) && \
		cargo helper instrument-kasan output/opensbi && \
		bash compile-opensbi.sh && \
		cargo helper generate-seed output/seed && \
		echo "> Preparation completed"; \
	else \
		echo "> Output directory already exists, skipping preparation. If you want to rebuild, run 'make clean' first"; \
	fi

run:
	@echo "> Running fuzzer..."
	cargo fuzzer --target output/opensbi/build/platform/generic/firmware/fw_dynamic.bin --injector ../../injector/build/injector.elf \
      --seed output/seed --output output/result

clean:
	@echo "> Cleaning up..."
	rm -rf output
	@echo "> Cleanup completed"
