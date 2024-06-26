#!/usr/bin/env bash

print_in_blue() {
    echo -e "\033[1;34m$1\033[0m"
}

print_in_blue "Creating python virtual environment..." && \
time ./scripts/venv.sh && \

print_in_blue "Compiling the program..." && \
time ./scripts/compile.sh && \

print_in_blue "Running the program..." && \
time ./scripts/run.sh
