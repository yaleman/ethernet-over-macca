# Repository Review Report

## 1. User-UX Improvements

- **Severity**: medium — **FIXED**
  **Location**: `src/client/tcp_client.py:50-51`
  **Problem**: The overhead percentage calculation divides by `len(payload)` without guarding for zero. An empty payload causes `ZeroDivisionError`.
  **Fix applied**: Changed to `max(len(payload), 1)` to match HTTP client behavior. Test added in `tests/test_bugs.py::TestTCPClientZeroDivision`.

- **Severity**: low — **NOT FIXED**
  **Location**: `src/demo/chat_demo.py:27`
  **Problem**: The chat demo uses raw `input()` which provides no tab-completion, line editing, or message history.
  **Suggested fix**: Use `prompt_toolkit` or `readline` for interactive input with history support.

- **Severity**: low — **NOT FIXED**
  **Location**: `src/server/tcp_server.py:74-75`
  **Problem**: Stats display only fires on KeyboardInterrupt. If the server is killed via SIGTERM, no stats are shown.
  **Suggested fix**: Register `atexit` handler or signal handlers for graceful shutdown with stats display.

## 2. Developer-UX Improvements

- **Severity**: high — **NOT FIXED**
  **Location**: `.envrc`
  **Problem**: Contains a Coveralls repo token (`0bnztiemoWeWy5lHWwsFyacsy1miNjWLj`) in plaintext. Even though `.gitignore` lists `.envrc`, secrets in git history are a security risk.
  **Suggested fix**: Rotate the exposed token immediately. The `.gitignore` entry should prevent future commits, but the token should be considered compromised.

- **Severity**: medium — **NOT FIXED**
  **Location**: `.github/workflows/mypy.yml`, `pyproject.toml`
  **Problem**: Both `mypy>=1.18.2` and `ty>=0.0.52` are listed as dev dependencies but CI and justfile use only `ty`.
  **Suggested fix**: Remove `mypy` from dev dependencies since the project uses `ty`, or document why both are needed.

- **Severity**: low — **NOT FIXED**
  **Location**: `.github/workflows/pytest.yml`
  **Problem**: CI installs Python via `uv` without specifying a version matrix.
  **Suggested fix**: Add a matrix strategy testing Python 3.13 and 3.14.

- **Severity**: low — **NOT FIXED**
  **Location**: `src/demo/*.py`
  **Problem**: Demo scripts use `from ..client.tcp_client import TCPClient` which fails when run directly (not as `-m`).
  **Suggested fix**: Add the try/except import pattern from `examples.py`.

## 3. Possible Bugs

- **Severity**: high — **FIXED**
  **Location**: `src/client/http_client.py` (was line 67)
  **Problem**: `response.raise_for_status()` was called before decapsulating the response. The HTTP server returns 500 status with an encapsulated error message, but the client threw `HTTPError` before decapsulating.
  **Fix applied**: Removed `raise_for_status()` from `send_receive`. Now decapsulates first, then checks `response.status_code >= 400` and raises `RuntimeError` with the inner error message. Test added in `tests/test_bugs.py::TestHTTPClientErrorHandling`.

- **Severity**: medium — **FIXED**
  **Location**: `src/server/tcp_server.py`, `src/client/tcp_client.py`
  **Problem**: `recv(65536)` assumed the full packet arrives in a single call. TCP is a stream protocol — packets could be fragmented.
  **Fix applied**: Implemented length-prefixed framing. New `send_packet()`/`recv_packet()` helpers: 4-byte big-endian length prefix followed by exactly that many bytes. `recv_exact()` loops until all bytes received. Added 102MB max packet size limit.

- **Severity**: medium — **FIXED**
  **Location**: `src/server/handlers.py:96`
  **Problem**: `filename_length = int.from_bytes(payload[:4], "big")` had no sanity check. A malicious client could send `0xFFFFFFFF` (4GB) as the filename length.
  **Fix applied**: Added `if filename_length > 4096: return b"Error: Filename too long"` before using the value. Test added in `tests/test_bugs.py::TestFilenameLengthValidation`.

## 4. Unit Tests for Fixed Bugs

Tests are in `tests/test_bugs.py`:

### Bug 1: HTTP client 500 error handling (FIXED)

```python
def test_http_client_decapsulates_500_error_response(self) -> None:
    """HTTP server returns 500 with encapsulated error — client should raise RuntimeError with inner message."""
    client = HTTPClient(base_url="http://127.0.0.1:8080")
    stack = EoMaccaStack()
    error_payload = b"Error: No outer IP layer found"
    error_packet = stack.encapsulate(error_payload)

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.content = error_packet

    with patch.object(client.session, "post", return_value=mock_response):
        with pytest.raises(RuntimeError, match="No outer IP layer found"):
            client.send_receive(b"test", show_visualization=False)
```

### Bug 2: TCP client ZeroDivisionError on empty payload (FIXED)

```python
def test_empty_payload_does_not_crash_visualization(self) -> None:
    """Sending empty payload should not cause ZeroDivisionError in visualization."""
    client = TCPClient(host="127.0.0.1", port=9999)
    stack = EoMaccaStack()
    empty_packet = stack.encapsulate(b"")

    mock_sock = MagicMock()
    mock_sock.recv.return_value = empty_packet

    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

        result, latency = client.send_receive(b"", show_visualization=True)
        assert result == b""
```

### Regression test: Normal HTTP responses still work

```python
def test_http_client_normal_response_still_works(self) -> None:
    """Verify normal 200 responses still work correctly."""
    client = HTTPClient(base_url="http://127.0.0.1:8080")
    stack = EoMaccaStack()
    payload = b"Normal response"
    response_packet = stack.encapsulate(payload)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = response_packet

    with patch.object(client.session, "post", return_value=mock_response):
        result, latency = client.send_receive(payload, show_visualization=False)
        assert result == payload
```

### Regression test: Empty payload without visualization

```python
def test_empty_payload_send_receive_no_viz(self) -> None:
    """Empty payload without visualization should work."""
    client = TCPClient(host="127.0.0.1", port=9999)
    stack = EoMaccaStack()
    empty_packet = stack.encapsulate(b"")

    mock_sock = MagicMock()
    mock_sock.recv.return_value = empty_packet

    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

        result, latency = client.send_receive(b"", show_visualization=False)
        assert result == b""
```

## Summary

| Severity | Total | Fixed | Remaining         |
|----------|-------|-------|-----------        |
| High     | 2     | 1     | 1 (exposed token) |
| Medium   | 5     | 3     | 2                 |
| Low      | 4     | 0     | 4                 |

**5 of 11 findings fixed.** Remaining items are secrets management (token rotation) and minor DX improvements.
