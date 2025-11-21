# Ethernet over Macca (EoMacca)

RFC 9999 implementation: Ethernet over IP over TCP over DNS over HTTP over TCP over IP over Ethernet. Because 8 layers of encapsulation seemed reasonable.

## What This Is

A fully functional (and absurd) protocol stack that wraps Ethernet frames in 7 additional protocol layers, achieving ~3000% overhead for small packets. Includes working client/server implementation, RFC specification, and Brainfuck code that outputs said RFC.

## Quick Start

```bash
# Install
uv sync --all-extras

# Terminal 1: Start server
just server-tcp echo

# Terminal 2: Run demo
just demo-echo
```

## Project Structure

```
├── docs/
│   ├── rfc-ethernet-over-macca.txt  # Full RFC specification (RFC 9999)
│   └── rfc-generator.bf              # Brainfuck code that outputs the RFC
├── src/
│   ├── protocol_stack.py             # Core EoMacca implementation
│   ├── encapsulation.py              # Layer-by-layer functions
│   ├── examples.py                   # Standalone usage examples
│   ├── server/
│   │   ├── tcp_server.py            # TCP socket server
│   │   ├── http_server.py           # HTTP/Flask server
│   │   └── handlers.py              # Request handlers (echo/chat/file/ping)
│   ├── client/
│   │   ├── tcp_client.py            # TCP client
│   │   └── ui.py                    # Terminal UI utilities
│   └── demo/
│       ├── echo_demo.py             # Echo demonstration
│       ├── chat_demo.py             # Interactive chat
│       ├── file_demo.py             # File transfer
│       └── ping_demo.py             # Latency measurement
├── tests/
│   └── test_protocol.py              # Protocol tests (18 tests, all passing)
├── brainfuck_rfc.pdf                 # PDF with Brainfuck code
├── justfile                          # Command shortcuts
└── pyproject.toml                    # Dependencies
```

## Using the Protocol Stack

```python
from src.protocol_stack import EoMaccaStack

stack = EoMaccaStack()

# Encapsulate data through 8 layers
packet = stack.encapsulate(b"Hello!")

# Decapsulate back to original
payload = stack.decapsulate(packet)

# Get overhead statistics
stats = stack.get_overhead_stats(b"Hello!")
# Returns: payload_size, total_size, header_size, overhead_ratio, efficiency_percent
```

## Running Servers

```bash
# TCP server (port 9999)
just server-tcp MODE    # MODE: echo, chat, file, ping

# HTTP server (port 8080)
just server-http MODE

# Examples
just server-tcp echo    # Echo back payloads
just server-tcp chat    # Chat server
just server-tcp file    # File receiver
just server-tcp ping    # Latency measurement
```

## Running Demos

All demos require a server running first.

```bash
just demo-echo          # Send test messages, verify echoes
just demo-chat          # Interactive chat session
just demo-file          # Transfer files, show overhead
just demo-ping          # Measure latency through 8 layers
just demo-all           # Run echo, file, and ping demos
```

## Available Commands

```bash
# Development
just check              # Run lint + typecheck + tests
just test               # Run pytest
just lint               # Run ruff linting
just typecheck          # Run mypy --strict
just format             # Format code

# Demonstrations
just example            # Run standalone examples
just server-tcp MODE    # Start TCP server
just server-http MODE   # Start HTTP server
just demo-*             # Run specific demo

# Artifacts
just build              # Generate Brainfuck code + PDF
just generate-brainfuck # Generate BF code only
just generate-pdf       # Generate PDF only
just stats              # Show project statistics
```

## Performance Characteristics

- **Overhead ratio**: 7:1 to 44:1 depending on payload size
- **Efficiency**: 2-15% (most of packet is headers)
- **Latency**: 5-10x baseline due to encapsulation
- **Example**: 15-byte payload becomes 456-byte packet (2940% overhead)

## File Descriptions

| File | Purpose |
|------|---------|
| `protocol_stack.py` | Main EoMacca class, full encapsulation/decapsulation |
| `encapsulation.py` | Individual layer functions (Ethernet->IP, IP->TCP, etc.) |
| `tcp_server.py` | Multi-threaded TCP server, handles EoMacca packets |
| `http_server.py` | Flask server with RFC-compliant `/eomacca/v1/tunnel` endpoint |
| `tcp_client.py` | Client for sending/receiving through protocol stack |
| `handlers.py` | Server logic for echo/chat/file/ping modes |
| `ui.py` | Rich terminal UI, colored output, statistics display |
| `*_demo.py` | Interactive demonstrations of protocol functionality |
| `rfc-ethernet-over-macca.txt` | Complete RFC specification document |
| `rfc-generator.bf` | Brainfuck code that outputs the RFC (280KB) |
| `brainfuck_rfc.pdf` | PDF containing the Brainfuck code |

## Testing

```bash
just test               # Run all 18 tests
just check              # Tests + linting + type checking
```

Tests cover:
- Individual layer encapsulation/decapsulation
- Full round-trip through all 8 layers
- Edge cases (empty payload, large payloads, binary data)
- Overhead calculations
- Error handling

## Troubleshooting

**"Connection refused"**
- Start server first: `just server-tcp echo`
- Check port 9999 is available

**"Module not found"**
- Run: `uv sync --all-extras`
- Use Python 3.12+

**Brainfuck interpreter hangs**
- The BF code is 280KB, execution is slow
- Use online interpreter or just read the PDF

## Why?

Educational demonstration of:
- Protocol encapsulation extremes
- Network overhead impact
- Python type safety (mypy --strict compliant)
- That "because we can" is valid engineering rationale

Based on the tradition of humorous technical RFCs (RFC 1149, RFC 2549, RFC 3514).

## License

Educational and entertainment purposes only. Do not use in production.
