# bHTTP: Binary HTTP Transport Protocol (`bserve` & `bcurl`)

A high-performance, low-latency binary transport protocol inspired by HTTP/2 framing (RFC 7540) and minimal HPACK header encoding (RFC 7541).

---

## Architecture Overview

- **`protocol.hpp`**: Protocol constants, 9-byte binary frame header structures, big-endian serialization/deserialization, static table dictionary, and streaming header codecs.
- **`bserve.cpp`**: Multi-threaded binary HTTP server with persistent keep-alive connection loop, strict `std::filesystem` path sandboxing (traversal prevention), unknown frame discard logic, and MIME resolution.
- **`bcurl.cpp`**: Binary HTTP CLI client with URL parsing, verbose debugging (`-v`), header inclusion (`-i`), output redirection (`-o`), raw hex dumping (`--raw-hex`), and protocol extensibility verification (`--send-unknown`).
- **`SPECIFICATION.md`**: Formal 2-page equivalent engineering specification of bHTTP/1.0.
- **`test_suite.py`**: Automated end-to-end integration and verification suite covering 8 test scenarios.

---

## Building the Project

Ensure a modern C++ compiler supporting C++20 (Apple Clang or GCC) and Make are installed:

```bash
make clean
make
```

This produces two standalone binaries:
- `bserve`
- `bcurl`

---

## Running `bserve`

```bash
./bserve <root_directory> <port>
```

Example:
```bash
./bserve ./www 9000
```

---

## Running `bcurl`

Fetch a file with default output:
```bash
./bcurl http://127.0.0.1:9000/hello.txt
```

Fetch with response headers included (`-i`):
```bash
./bcurl -i http://127.0.0.1:9000/hello.txt
```

Verbose connection and frame diagnostics (`-v`):
```bash
./bcurl -v http://127.0.0.1:9000/index.html
```

Display raw byte-by-byte hex dump of transmitted and received frames:
```bash
./bcurl --raw-hex http://127.0.0.1:9000/hello.txt
```

Test unknown frame extensibility (injects an unknown frame type `0x99` before GET):
```bash
./bcurl -v --send-unknown http://127.0.0.1:9000/hello.txt
```

---

## Running Automated Test Suite

```bash
python3 test_suite.py
```

Tests include:
1. Standard GET / 200 OK file retrieval.
2. Response headers validation (`-i`).
3. 404 Not Found error frame verification.
4. Directory traversal attack prevention (`/../../secret.txt`, `/..%2f`).
5. Persistent Keep-Alive connection loop (multiple sequential requests over a single TCP socket).
6. Extensibility rule (injecting unknown frame types `0x77` and `0xFE`, verifying server discards cleanly and keeps connection open).
7. Binary payload transfer integrity (64KB random data checksum verification).
8. Malformed frame handling (400 Bad Request).
