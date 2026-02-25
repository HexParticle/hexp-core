OS = $(shell uname)
EXT_LIBS = -lpcap
BASE_FLAGS = -I./include -fPIC -Wall -Wextra -pedantic -ggdb -O3 # -DRUN_MAIN
O_FLAGS := $(BASE_FLAGS)

LIB_BUILD_DIR := /usr/local/lib/HexParticle
OBJ_BUILD_DIR := ./build

SRC_DIR := ./src

ifeq ($(OS),Darwin)
	COMPILE_MSG = "====Compiling for MacOS===="
	CC = clang
	CC_FLAGS = -framework SystemConfiguration -framework CoreFoundation -shared $(BASE_FLAGS)
else
	COMPILE_MSG = "====Compiling for Linux===="
	CC = gcc
	CC_FLAGS = -shared $(BASE_FLAGS)
endif

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_BUILD_DIR)/%.o, $(SRCS)) # ---> patsubst(pattern, replacement, text) = pattern substitute

TARGET = $(LIB_BUILD_DIR)/libhexp.so

all: $(TARGET)

$(TARGET): $(OBJS) | $(LIB_BUILD_DIR)
	@echo $(COMPILE_MSG)
	$(CC) $(CC_FLAGS) $(OBJS) $(EXT_LIBS) -o $@

$(OBJ_BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(O_FLAGS) $< -o $@

$(LIB_BUILD_DIR):
	@mkdir -p $(LIB_BUILD_DIR)

$(OBJ_BUILD_DIR):
	@mkdir -p $(OBJ_BUILD_DIR)

.PHONY: clean
clean:
	rm -rf *.o main $(LIB_BUILD_DIR)/$(notdir $(TARGET)) $(OBJ_BUILD_DIR)