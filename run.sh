#!/bin/sh

OS_NAME=$(uname -s)

case "$OS_NAME" in
    Linux)
        echo "Running on Linux"
        ;;
    Darwin)
		echo "Compiling hexpdump for MacOS"
        clang -I./include -fPIC -Wall -Wextra -pedantic -ggdb -O3 -DRUN_MAIN \
			-framework SystemConfiguration -framework CoreFoundation -lpcap \
			./src/*.c ./src/netdsl/*.c ./src/sds/*.c -o hexpdump.macho
        ;;
    *)
        echo "Unknown OS: $OS_NAME"
        exit 1
        ;;
esac