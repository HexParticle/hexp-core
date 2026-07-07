OS 			= $(shell uname)
EXT_LIBS 	= -lpcap

BASE_FLAGS 	= -I./include -fPIC -Wall -Wextra -pedantic -ggdb -O3
O_FLAGS 	:= $(BASE_FLAGS)

LIB_BUILD_DIR 	:= /usr/local/lib/HexParticle
OBJ_BUILD_DIR 	:= ./build
CLI_BUILD_DIR 	:= ./build/target

SRC_DIR 		:= ./src
CLI_SRC_DIR 	:= ./src/cli

ALL_SRCS    := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/**/*.c)
CLI_SRCS 	:= $(wildcard $(CLI_SRC_DIR)/*.c) $(wildcard $(CLI_SRC_DIR)/**/*.c)
SRCS        := $(filter-out $(CLI_SRCS), $(ALL_SRCS))

ifeq ($(OS),Darwin)
	COMPILE_MSG = "====Compiling for MacOS===="
	CC 			= clang
	SO_FLAGS 	= -framework SystemConfiguration -framework CoreFoundation -shared $(BASE_FLAGS)
else
	COMPILE_MSG = "====Compiling for Linux===="
	CC 			= gcc
	SO_FLAGS 	= -shared $(BASE_FLAGS)
endif

OBJS 		= $(patsubst $(SRC_DIR)/%.c, $(OBJ_BUILD_DIR)/%.o, $(SRCS)) # ---> patsubst(pattern, replacement, text) = pattern substitute
CLI_OBJS 	= $(patsubst $(CLI_SRC_DIR)/%.c, $(CLI_BUILD_DIR)/%.o, $(CLI_SRCS))

TARGET 			= $(LIB_BUILD_DIR)/libhexp.so
CLI_TARGET 		= $(CLI_BUILD_DIR)/hexpdump

CLI_TARGET_LIBS = $(TARGET)

all: $(TARGET)

$(TARGET): $(OBJS) | $(LIB_BUILD_DIR)
	@echo $(COMPILE_MSG)
	$(CC) $(SO_FLAGS) $(OBJS) $(EXT_LIBS) -o $@

$(OBJ_BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(O_FLAGS) $< -o $@

$(LIB_BUILD_DIR):
	@mkdir -p $(LIB_BUILD_DIR)

$(OBJ_BUILD_DIR):
	@mkdir -p $(OBJ_BUILD_DIR)


# ===== CLI =====

# i will be generating the lib first and then use it to build the CLI dumper
hexpdump: $(TARGET) $(CLI_OBJS) | $(CLI_BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(BASE_FLAGS) -o $(CLI_BUILD_DIR)/$@ $(CLI_OBJS) $(TARGET)

$(CLI_BUILD_DIR)/%.o: $(CLI_SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(O_FLAGS) $< -o $@

$(CLI_BUILD_DIR):
	@mkdir -p $(CLI_BUILD_DIR)

# ===== CLI =====


.PHONY: clean hexpdump
clean:
	rm -rf *.o main $(LIB_BUILD_DIR)/$(notdir $(TARGET)) $(OBJ_BUILD_DIR)