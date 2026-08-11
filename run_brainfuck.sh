#!/bin/bash

echo "Running Brainfuck interpreter to generate the RFC..."

if command -v brainfuck >/dev/null 2>&1; then
    brainfuck docs/rfc-generator-v1.0.bf
else
    echo "Error: 'brainfuck' command not found."
    echo "Install with: 'brew install brainfuck' or figure out another parser."
    exit 1
fi