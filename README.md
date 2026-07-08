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

```text
├── docs/
│   ├── rfc-ethernet-over-macca-v1.txt  # Full v1 RFC specification (RFC 9999)
│   └── rfc-generator.bf              # Brainfuck code that outputs the RFC
├── src/
│   ├── ethernet_over_macca/
│   │   ├── protocol_stack.py         # Core EoMacca implementation
│   │   ├── encapsulation.py          # Layer-by-layer functions
│   │   ├── cli.py                    # Shared --layers and mode parsing
│   │   └── stats.py                  # Payload overhead statistics
│   ├── eom_server/
│   │   ├── tcp_server.py             # TCP socket server
│   │   ├── http_server.py            # HTTP/Flask server
│   │   └── handlers.py               # Request handlers (echo/chat/file/ping)
│   ├── eom_client/
│   │   ├── tcp_client.py             # TCP client
│   │   ├── http_client.py            # HTTP tunnel client
│   │   └── ui.py                     # Terminal UI utilities
│   ├── demo/
│   │   ├── echo_demo.py              # Echo demonstration
│   │   ├── chat_demo.py              # Interactive chat
│   │   ├── file_demo.py              # File transfer
│   │   └── ping_demo.py              # Latency measurement
│   └── examples.py                   # Standalone usage examples
├── tests/
│   ├── test_protocol.py              # Protocol stack and layer tests
│   ├── test_integration.py           # TCP server/client integration tests
│   ├── test_http_server.py           # HTTP server/client tests
│   └── ...                           # 167 tests collected
├── brainfuck_rfc.pdf                 # PDF with Brainfuck code
├── justfile                          # Command shortcuts
└── pyproject.toml                    # Dependencies
```

## Using the Protocol Stack

```python
from ethernet_over_macca.protocol_stack import EoMaccaStack

stack = EoMaccaStack()

# Or choose a custom v2 layer order. The server and client must match.
custom_stack = EoMaccaStack(layer_order="THDTIE")

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

## Custom Layer Ordering

The configurable layer stack (v2) lets you choose your own layer sequence
out-of-band; the sender and receiver must agree. The default reproduces
the v1 wire format.

The five configurable layers, each identified by a single character in the
order string:

| Char | Layer         |
| ---- | ------------- |
| `E`  | Ethernet      |
| `I`  | IP            |
| `T`  | TCP (over IP) |
| `D`  | DNS (TXT)     |
| `H`  | HTTP          |

The order string is read outer -> inner. The parser ignores whitespace and is
case-insensitive, but the documented canonical form is uppercase. The outermost
character must be `T` or `I` because it carries the outer IP envelope. So
`"THDTIE"` decodes as
`TCP -> HTTP -> DNS -> TCP -> IP -> Ethernet`.

```bash
# Just recipes accept the layer order as a recipe argument
just server-tcp echo THDTIE
just demo-echo THDTIE

# HTTP server recipes work the same way
just server-http echo THDTIE

# Direct Python entrypoints accept --layers ORDER
uv run python -m eom_server.tcp_server echo --layers THDTIE
uv run python -m demo.echo_demo --layers THDTIE
```

See `parse_layer_order` in `src/ethernet_over_macca/encapsulation.py` for
the parser and `src/ethernet_over_macca/cli.py` for the CLI plumbing.

## Running Demos

All demos require a server running first.

```bash
just demo-echo          # Send test messages, verify echoes
just demo-chat          # Interactive chat session
just demo-file          # Transfer files, show overhead
just demo-ping          # Measure latency through 8 layers
just demo-echo THDTIE   # Run a demo with a custom layer order
```

## Available Commands

```bash
# Development
just check              # Run lint + typecheck + tests
just test               # Run pytest
just lint               # Run ruff linting
just typecheck          # Run ty
just format             # Format code

# Demonstrations
just example            # Run standalone examples
just server-tcp MODE    # Start TCP server
just server-http MODE   # Start HTTP server
just server-tcp MODE LAYERS
                         # Start TCP server with a custom layer order
just server-http MODE LAYERS
                         # Start HTTP server with a custom layer order
just demo-*             # Run specific demo
just demo-* LAYERS      # Run specific demo with a custom layer order

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
- **Example**: 15-byte payload becomes a 457-byte packet (2946.7% overhead)

## File Descriptions

| File | Purpose |
| ------ | --------- |
| `src/ethernet_over_macca/protocol_stack.py` | Main EoMacca class, full encapsulation/decapsulation |
| `src/ethernet_over_macca/encapsulation.py` | Individual layer functions and layer-order parsing |
| `src/ethernet_over_macca/cli.py` | Shared server/demo argument parsing |
| `src/eom_server/tcp_server.py` | Multi-threaded TCP server, handles EoMacca packets |
| `src/eom_server/http_server.py` | Flask server with RFC-compliant `/eomacca/v1/tunnel` endpoint |
| `src/eom_server/handlers.py` | Server logic for echo/chat/file/ping modes |
| `src/eom_client/tcp_client.py` | TCP client for sending/receiving through protocol stack |
| `src/eom_client/http_client.py` | HTTP client for the tunnel endpoint |
| `src/eom_client/ui.py` | Rich terminal UI, colored output, statistics display |
| `src/demo/*_demo.py` | Interactive demonstrations of protocol functionality |
| `docs/rfc-ethernet-over-macca-v1.txt` | Complete v1 RFC specification document |
| `docs/rfc-generator.bf` | Brainfuck code that outputs the RFC (about 276K) |
| `brainfuck_rfc.pdf` | PDF containing the Brainfuck code |

## Testing

```bash
just test               # Run all 167 tests
just check              # Tests + linting + type checking
```

Tests cover:

- Individual layer encapsulation/decapsulation
- Full round-trip through all 8 layers
- Custom v2 layer orderings
- TCP and HTTP server/client flows
- Edge cases (empty payload, large payloads, binary data)
- Overhead calculations
- Error handling

## Troubleshooting

### "Connection refused"

- Start server first: `just server-tcp echo`
- Check port 9999 is available

### "Module not found"

- Run: `uv sync --all-extras`
- Use Python 3.13+

### Brainfuck interpreter hangs

- The BF code is about 276K, execution is slow
- Use online interpreter or just read the PDF

## Why?

Educational demonstration of:

- Protocol encapsulation extremes
- Network overhead impact
- Python type safety
- That "because we can" is valid engineering rationale

Based on the tradition of humorous technical RFCs (RFC 1149, RFC 2549, RFC 3514).

## License

Educational and entertainment purposes only. Do not use in production.
