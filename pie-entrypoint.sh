#!/usr/bin/env bash

cat > program_input.json && \

cairo-run \
    --program program_compiled.json \
    --layout recursive \
    --program_input program_input.json \
    --cairo_pie_output program_pie.bin && \

cat program_pie.bin
