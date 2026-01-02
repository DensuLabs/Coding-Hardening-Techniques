# Defaults (can be overridden on command line)
ARCH ?= x86_64
CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -fPIC

# Paths
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build/$(ARCH)
EXAMPLES_DIR = examples

# Files
SRC = $(SRC_DIR)/SecureBuffer.cpp
OBJ = $(BUILD_DIR)/SecureBuffer.o
STATIC_LIB = $(BUILD_DIR)/libsecureBuffer.a
SHARED_LIB = $(BUILD_DIR)/libsecureBuffer.so
MAIN = $(BUILD_DIR)/main
MAIN_SRC = $(EXAMPLES_DIR)/Main.cpp

# Default target
all: $(STATIC_LIB) $(SHARED_LIB) $(MAIN)

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build object file
$(OBJ): $(SRC) $(INC_DIR)/SecureBuffer.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $(SRC) -o $(OBJ)

# Build static library
$(STATIC_LIB): $(OBJ)
	ar rcs $(STATIC_LIB) $(OBJ)

# Build shared library
$(SHARED_LIB): $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ)

# Build example program
$(MAIN): $(MAIN_SRC) $(STATIC_LIB)
	$(CC) $(CFLAGS) -I$(INC_DIR) $(MAIN_SRC) -L$(BUILD_DIR) -lsecureBuffer -o $(MAIN)

# Run program (with shared lib)
run: $(MAIN)
	LD_LIBRARY_PATH=$(BUILD_DIR) ./$(MAIN)

# Clean for one arch
clean:
	rm -rf $(BUILD_DIR)

# Clean all arch builds
distclean:
	rm -rf build/*
