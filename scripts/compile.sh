#!/usr/bin/env bash

source .venv/bin/activate && \
cairo-compile \
  src/main.cairo \
  --output resources/main_compiled.json \
  --proof_mode && \
deactivate
