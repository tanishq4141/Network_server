# Binary HTTP Protocol Specification (bHTTP/1.0)
**Status**: Standards Track / Formal Engineering Specification  
**Version**: 1.0.0  
**Transport**: TCP (Stream-oriented, Big-Endian Network Byte Order)  

---

## 1. Abstract & Scope
This specification defines **bHTTP/1.0**, a low-latency, binary application transport protocol inspired by HTTP/2 framing (RFC 7540) and compact static table compression (RFC 7541). The protocol eliminates textual parsing ambiguities, delimiter sniffing, and head-of-line string scanning by utilizing fixed-width binary frame headers, indexed metadata tables, and length-delimited payloads.

---

## 2. Frame Layout (Fixed-Size Header)

Every frame transferred over a bHTTP TCP connection begins with an immutable **9-octet (72-bit)** header, followed by a variable-length payload of `Length` bytes.

```
+---------------------------------------------------------------+
|                       Length (24 bits)                        |
+---------------+---------------+-------------------------------+
|   Type (8)    |   Flags (8)   |
+---+-----------+---------------+-------------------------------+
| R |                    Stream Identifier (31 bits)            |
+---+-----------------------------------------------------------+
|                     Frame Payload (0 ... Length octets)       |
+---------------------------------------------------------------+
```

### Field Width Definitions and Engineering Justifications

| Field | Width | Type | Semantics & Justification |
| :--- | :--- | :--- | :--- |
| **Length** | 24 bits | Unsigned Integer | Payload length in octets ($0 \dots 2^{24}-1 = 16,777,215$ bytes / $\approx 16$ MB). **Justification**: A 24-bit window provides the ideal balance between single-frame throughput (transferring full web assets, media chunks, and binary objects without premature fragmentation) and memory bounds (capping frame buffering at 16 MB to prevent memory exhaustion DoS attacks). |
| **Type** | 8 bits | Unsigned Integer | Identifies frame semantics ($0 \dots 255$). **Justification**: 256 frame types permit standard foundational semantics (`0x01`–`0x04`) while reserving over 250 opcodes for protocol evolution and extensions without altering the fixed framing structure. |
| **Flags** | 8 bits | Bitmask | Per-frame control signals ($0 \dots 255$). **Justification**: 8 boolean slots allow in-band signaling (`END_STREAM`, `END_HEADERS`, `ACK`) directly on the frame header, eliminating extra round-trips and auxiliary control frames. |
| **R** | 1 bit | Reserved | Must be sent as `0x00`; receivers MUST ignore this bit. |
| **Stream ID** | 31 bits | Unsigned Integer | Stream identifier ($0 \dots 2^{31}-1 = 2,147,483,647$). **Justification**: Over 2.1 billion concurrent or sequential multiplexed streams per persistent TCP connection, preventing stream ID exhaustion over long-lived sessions. Stream `0x00000000` is reserved for connection-level frames. |

### Core Frame Types
* `0x01` (**HEADERS**): Carries binary-encoded metadata key-value pairs.
* `0x02` (**DATA**): Carries raw message application data (file contents, request bodies).
* `0x03` (**SETTINGS / PING**): Connection-level parameter exchange or heartbeat diagnostics.
* `0x04` (**GOAWAY**): Graceful session teardown indicating connection termination.

### Defined Flags
* `0x01` (**END_STREAM**, Bit 0): Indicates that this frame is the terminal transmission from the sender for the designated Stream ID.
* `0x02` (**END_HEADERS**, Bit 1): Indicates that the header block is fully delivered within this frame.
* `0x04` (**ACK**, Bit 2): Acknowledgment flag for SETTINGS/PING frames.

---

## 3. Extensibility & The Unknown Frame Processing Rule

To guarantee forward and backward compatibility across heterogeneous implementations:

> **Mandatory Receiver Rule**:
> A receiver encountering a Frame Type that it does not recognize or support **MUST** read exactly `Length` octets of payload from the socket and discard them cleanly. The receiver **MUST NOT** alter the stream state machine, **MUST NOT** return an error, and **MUST NOT** terminate the TCP connection.

This enables forward deployment of novel frames (e.g., `0x05` PRIORITY, `0x06` PUSH_PROMISE, `0x10` METRICS) without disrupting existing infrastructure.

---

## 4. Minimal Binary Header Encoding (Static Table + Length Prefix)

Header blocks are packed sequences of field entries without external delimiters.

### A. Static Indexed Table (Indices 0–9)
The protocol predefines a static dictionary mapping the 10 most common HTTP headers to single-byte indices:

| Index | Binary Value | Header Name | Primary Role |
| :---: | :---: | :--- | :--- |
| `0` | `0x00` | `:method` | Pseudo-header: HTTP method (GET, POST, etc.) |
| `1` | `0x01` | `:path` | Pseudo-header: Request URI path |
| `2` | `0x02` | `:status` | Pseudo-header: Response 3-digit status code |
| `3` | `0x03` | `content-type` | MIME type descriptor |
| `4` | `0x04` | `content-length` | Byte size of payload |
| `5` | `0x05` | `server` | Server software identifier |
| `6` | `0x06` | `user-agent` | Client software identifier |
| `7` | `0x07` | `host` | Authority / target domain |
| `8` | `0x08` | `date` | Timestamp (RFC 1123 format) |
| `9` | `0x09` | `connection` | Connection persistence directive |

### B. Header Entry Formats
Headers are encoded under two primary representations:

1. **Static Indexed Header Entry**:
   ```
   [table_index: 1 byte][val_len: 2 bytes Big-Endian][val_str: val_len bytes]
   ```
   * `table_index`: 1 byte representing indices `0x00` through `0x09` (or `0x80` through `0x89` when HPACK MSB index flag is enabled).
   * `val_len`: 16-bit unsigned integer ($0 \dots 65,535$) specifying the byte length of the value.
   * `val_str`: Raw UTF-8 bytes of the value string.

2. **Dynamic / Literal Header Entry**:
   ```
   [name_len: 2 bytes Big-Endian][name_str: name_len bytes][val_len: 2 bytes Big-Endian][val_str: val_len bytes]
   ```
   * `name_len`: 16-bit unsigned integer ($1 \dots 65,535$) specifying the byte length of the custom header key.
   * `name_str`: Raw UTF-8 bytes of the custom header key.
   * `val_len`: 16-bit unsigned integer specifying value length.
   * `val_str`: Raw UTF-8 bytes of the value.

---

## 5. Connection Lifecycle & Persistence (Keep-Alive)

1. **Connection Establishment**: Client connects via standard TCP socket.
2. **Stream Multiplexing**:
   * Client-initiated streams utilize odd integers (`1, 3, 5, ...`).
   * Stream `0` is strictly reserved for connection control (`SETTINGS`, `GOAWAY`).
3. **Keep-Alive Loop**: Connections remain persistent indefinitely across successive transactions. The server does not close the connection after serving a request; it waits for subsequent frames on the same connection.
4. **Graceful Shutdown**:
   * Either endpoint initiates graceful teardown by sending a `GOAWAY` frame (`Type 0x04`, `Stream ID 0`, payload containing `[Last-Stream-ID: 4B][Error-Code: 4B]`).
   * Upon receiving `GOAWAY`, the socket is closed cleanly without dropped in-flight frames.

---

## 6. Security & Sandboxing Considerations

* **Strict Path Sandboxing**: The server canonicalizes all incoming `:path` values against `<root_directory>`. Directory traversal patterns (`..`, `%2e%2e`, `/../`) are evaluated and forbidden. Requests attempting to reference resources outside `<root_directory>` receive `:status 404` or `:status 403`.
* **Resource Bounds**: Payloads exceeding 16 MB or headers with truncated lengths trigger an immediate `:status 400` frame.
