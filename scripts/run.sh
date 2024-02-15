#!/usr/bin/env bash

source .venv/bin/activate && \
cairo-run \
  --program resources/main_compiled.json \
  --layout recursive \
  --print_output \
  --trace_file resources/main_trace.bin \
  --memory_file resources/main_memory.bin \
  --air_public_input resources/main_public_input.json \
  --air_private_input resources/main_private_input.json \
  --program_input src/input.json \
  --proof_mode && \
deactivate
