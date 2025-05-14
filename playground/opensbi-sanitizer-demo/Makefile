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
		(cd output/opensbi && git apply ../../kasan-test.patch) && \
		bash compile-opensbi.sh && \
		cargo helper generate-seed output/seed && \
		echo "> Preparation completed"; \
	else \
		echo "> Output directory already exists, skipping preparation. If you want to rebuild, run 'make clean' first"; \
	fi

run:
	@echo "> Running fuzzer..."
	cargo fuzzer --target output/opensbi/build/platform/generic/firmware/fw_dynamic.bin --injector ../../injector/build/injector.elf \
      --seed output/seed --output output/result --skip-halt --skip-inputs 4,5,6,7,0x504D55:2

clean:
	@echo "> Cleaning up..."
	rm -rf output
	@echo "> Cleanup completed"

run-demo: prepare
ifndef TARGET
	$(error TARGET is not set)
endif
	@echo "> Running demo..."
	cargo helper run output/opensbi/build/platform/generic/firmware/fw_dynamic.bin ../../injector/build/injector.elf $(TARGET)
