# Makefile for t_cosign

# Compiler settings
CC := gcc
CFLAGS := -Wall  
LDFLAGS := -lcrypto -ldl
INCS := -I./src/

# Directories
SRC_DIR := src
T_DIR := t
BUILD_DIR := build

# File names
EXEC := t_cosign
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
T_FILES := $(wildcard $(T_DIR)/*.c)

# Object files
SRC_OBJ := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))
T_OBJ := $(patsubst $(T_DIR)/%.c, $(BUILD_DIR)/%.o, $(T_FILES))

# Targets
all: $(EXEC)

$(EXEC): $(SRC_OBJ) $(T_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

$(BUILD_DIR)/%.o: $(T_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(EXEC)

.PHONY: all clean
