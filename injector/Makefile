CC = riscv64-unknown-elf-gcc
LD = riscv64-unknown-elf-ld

CFLAGS = -march=rv64imac -mabi=lp64 -mcmodel=medany -Isrc
LDFLAGS = -T src/linker.ld --no-warn-rwx-segments

BUILD_DIR = build
SRC_DIR = src
TARGET = $(BUILD_DIR)/injector.elf
SOURCES = $(SRC_DIR)/injector.c
OBJECTS = $(BUILD_DIR)/injector.o

PREFIX ?= >>>

.PHONY: compile clean

compile: $(TARGET)
	@echo "$(PREFIX) Build completed successfully"
	@echo "$(PREFIX) Output: $(TARGET)"

$(BUILD_DIR):
	@echo "$(PREFIX) Creating build directory..."
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "$(PREFIX) Compiling $<..."
	@$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJECTS)
	@echo "$(PREFIX) Linking object files..."
	@$(LD) $(LDFLAGS) -o $@ $^

clean:
	@echo "$(PREFIX) Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "$(PREFIX) Clean completed"
