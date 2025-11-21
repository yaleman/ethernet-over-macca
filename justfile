# Justfile for EoMacca project

# Default recipe - show available commands
default:
    @just --list

# Run all checks (lint, type check, test)
check: lint typecheck test
    @echo "✓ All checks passed!"

# Run tests
test:
    uv run pytest tests/ -v

# Run tests with coverage report
test-coverage:
    uv run coverage run --source=src -m pytest
    uv run coveralls

# Run tests and check coverage threshold
test-coverage-check:
    uv run pytest --cov=src --cov-fail-under=85 --cov-report=term tests/ -v

# Run type checking with mypy
typecheck:
    uv run mypy --strict src/ tests

# Run linting with ruff
lint:
    uv run ruff check src/ tests/

# Format code with ruff
format:
    uv run ruff format src/ tests/

# Run the example code
example:
    uv run python -m src.examples

# Start TCP server in echo mode
server-tcp mode="echo":
    uv run python -m src.server.tcp_server {{mode}}

# Start HTTP server
server-http mode="echo":
    uv run python -m src.server.http_server {{mode}}

# Run echo demo (requires server running)
demo-echo:
    uv run python -m src.demo.echo_demo

# Run chat demo (requires server running)
demo-chat:
    uv run python -m src.demo.chat_demo

# Run file transfer demo (requires server running)
demo-file:
    uv run python -m src.demo.file_demo

# Run ping/latency demo (requires server running)
demo-ping:
    uv run python -m src.demo.ping_demo

# Run all demos in sequence (requires server running)
demo-all: demo-echo demo-file demo-ping
    @echo "✓ All demos complete!"

# Generate Brainfuck code from RFC
generate-brainfuck:
    uv run python src/brainfuck_generator.py

# Generate PDF with Brainfuck code
generate-pdf:
    uv run python src/pdf_generator.py

# Build everything (BF code and PDF)
build: generate-brainfuck generate-pdf
    @echo "✓ Build complete!"

# Run a Brainfuck interpreter on the generated code (requires bf package)
run-brainfuck:
    @echo "Running Brainfuck interpreter (this may take a while)..."
    @if command -v bf >/dev/null 2>&1; then \
        bf docs/rfc-generator.bf | head -100; \
        echo "..."; \
        echo "(output truncated, full RFC is ~20KB)"; \
    else \
        echo "Error: 'bf' command not found. Install with: pip install bf"; \
        exit 1; \
    fi

# Clean generated files
clean:
    rm -f docs/rfc-generator.bf
    rm -f brainfuck_rfc.pdf
    rm -rf .mypy_cache
    rm -rf .pytest_cache
    rm -rf __pycache__
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    @echo "✓ Cleaned generated files"

# Install development dependencies
install:
    uv sync --all-extras

# Show project statistics
stats:
    @echo "Project Statistics:"
    @echo "=================="
    @ls -lh docs/rfc-ethernet-over-macca.txt | awk '{print "RFC size:     " $$5}'
    @if [ -f docs/rfc-generator.bf ]; then \
        ls -lh docs/rfc-generator.bf | awk '{print "BF code size: " $$5}'; \
    fi
    @if [ -f brainfuck_rfc.pdf ]; then \
        ls -lh brainfuck_rfc.pdf | awk '{print "PDF size:     " $$5}'; \
    fi
    @echo ""
    @echo "Python code:"
    @find src -name "*.py" -exec wc -l {} + | tail -1
    @echo ""
    @echo "Test code:"
    @find tests -name "*.py" -exec wc -l {} + 2>/dev/null | tail -1 || echo "No tests yet"
