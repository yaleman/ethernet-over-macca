# Justfile for EoMacca project

# Default recipe - show available commands
default:
    @just --list

# Run all checks (lint, type check, test)
check: lint typecheck test
    @echo "✓ All checks passed!"

# Run tests
test:
    uv run pytest -q

# Run tests with coverage report
test-coverage:
    uv run coverage run -m pytest
    uv run coveralls

# Run tests and check coverage threshold
test-coverage-check:
    uv run pytest --cov=src --cov-fail-under=85 --cov-report=term tests/ -v

# Run type checking
typecheck:
    uv run ty check

# Run linting with ruff
lint:
    uv run ruff check

# Format code with ruff
format:
    uv run ruff format

# Run the example code
example:
    uv run python -m src.examples

# Start TCP server in echo mode (pass layers='THDtIE' to override the default)
server-tcp mode="echo" layers='':
    @if [ -n "{{layers}}" ]; then \
        uv run python -m eom_server.tcp_server {{mode}} --layers {{layers}}; \
    else \
        uv run python -m eom_server.tcp_server {{mode}}; \
    fi

# Start HTTP server (pass layers='THDtIE' to override the default)
server-http mode="echo" layers='':
    @if [ -n "{{layers}}" ]; then \
        uv run python -m eom_server.http_server {{mode}} --layers {{layers}}; \
    else \
        uv run python -m eom_server.http_server {{mode}}; \
    fi

# Run echo demo (requires server running); pass layers='THDtIE' to override
demo-echo layers='':
    @if [ -n "{{layers}}" ]; then \
        uv run python -m demo.echo_demo --layers {{layers}}; \
    else \
        uv run python -m demo.echo_demo; \
    fi

# Run chat demo (requires server running - 'just server-tcp chat')
demo-chat layers='':
    @if [ -n "{{layers}}" ]; then \
        uv run python -m demo.chat_demo --layers {{layers}}; \
    else \
        uv run python -m demo.chat_demo; \
    fi

# Run file transfer demo (requires server running)
demo-file layers='':
    @if [ -n "{{layers}}" ]; then \
        uv run python -m demo.file_demo --layers {{layers}}; \
    else \
        uv run python -m demo.file_demo; \
    fi

# Run ping/latency demo (requires server running)
demo-ping layers='':
    @if [ -n "{{layers}}" ]; then \
        uv run python -m demo.ping_demo --layers {{layers}}; \
    else \
        uv run python -m demo.ping_demo; \
    fi

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
    ./run-brainfuck.sh

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
    @ls -lh docs/rfc-ethernet-over-macca-v1.txt | awk '{print "RFC v1 size:     " $$5}'
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
