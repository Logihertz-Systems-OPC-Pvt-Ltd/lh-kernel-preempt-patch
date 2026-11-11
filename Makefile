CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -pedantic -Iinclude
LDFLAGS ?= -lm

SRC = src/latency_math.c src/config_parser.c src/patch_engine.c src/rt_auditor.c src/exporters.c
MAIN_SRC = src/main.c
TEST_SRC = tests/test_runner.c

BIN_DIR = bin
BUILD_DIR = build
TARGET = $(BIN_DIR)/lh-preempt
TEST_TARGET = tests/test_runner

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(SRC) $(MAIN_SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SRC) $(MAIN_SRC) -o $(TARGET) $(LDFLAGS)

$(TEST_TARGET): $(SRC) $(TEST_SRC)
	$(CC) $(CFLAGS) $(SRC) $(TEST_SRC) -o $(TEST_TARGET) $(LDFLAGS)

test: $(TEST_TARGET) $(TARGET)
	@echo "Running C11 Real-Time Verification Test Suite..."
	@./$(TEST_TARGET)

clean:
	rm -rf $(BIN_DIR) $(BUILD_DIR) $(TEST_TARGET) dist/
