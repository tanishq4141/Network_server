#!/usr/bin/env python3
import socket
import struct
import subprocess
import time
import os
import sys

PORT = 9123
ROOT_DIR = os.path.abspath("./www")

# Protocol constants
FRAME_HEADER_SIZE = 9
TYPE_HEADERS = 0x01
TYPE_DATA = 0x02
TYPE_SETTINGS = 0x03
TYPE_GOAWAY = 0x04

FLAG_NONE = 0x00
FLAG_END_STREAM = 0x01
FLAG_END_HEADERS = 0x02

STATIC_TABLE = [
    ":method",
    ":path",
    ":status",
    "content-type",
    "content-length",
    "server",
    "user-agent",
    "host",
    "date",
    "connection"
]

def serialize_frame(length, ftype, flags, stream_id, payload=b""):
    hdr = struct.pack(">IBB", (length << 8) | ftype, flags, (stream_id >> 24) & 0x7F)
    # 24-bit length, 8-bit type, 8-bit flags, 32-bit stream id
    hdr_bytes = bytearray(9)
    hdr_bytes[0] = (length >> 16) & 0xFF
    hdr_bytes[1] = (length >> 8) & 0xFF
    hdr_bytes[2] = length & 0xFF
    hdr_bytes[3] = ftype
    hdr_bytes[4] = flags
    hdr_bytes[5] = (stream_id >> 24) & 0x7F
    hdr_bytes[6] = (stream_id >> 16) & 0xFF
    hdr_bytes[7] = (stream_id >> 8) & 0xFF
    hdr_bytes[8] = stream_id & 0xFF
    return bytes(hdr_bytes) + payload

def parse_frame_header(data):
    length = (data[0] << 16) | (data[1] << 8) | data[2]
    ftype = data[3]
    flags = data[4]
    stream_id = ((data[5] & 0x7F) << 24) | (data[6] << 16) | (data[7] << 8) | data[8]
    return length, ftype, flags, stream_id

def encode_headers(headers):
    out = bytearray()
    for name, val in headers:
        if name in STATIC_TABLE:
            idx = STATIC_TABLE.index(name)
            out.append(idx)
            val_bytes = val.encode("utf-8")
            out.extend(struct.pack(">H", len(val_bytes)))
            out.extend(val_bytes)
        else:
            name_bytes = name.encode("utf-8")
            val_bytes = val.encode("utf-8")
            out.extend(struct.pack(">H", len(name_bytes)))
            out.extend(name_bytes)
            out.extend(struct.pack(">H", len(val_bytes)))
            out.extend(val_bytes)
    return bytes(out)

def decode_headers(payload):
    headers = []
    i = 0
    size = len(payload)
    while i < size:
        first = payload[i]
        if first & 0x80:
            idx = first & 0x7F
            i += 1
            vlen = struct.unpack(">H", payload[i:i+2])[0]
            i += 2
            val = payload[i:i+vlen].decode("utf-8", errors="replace")
            i += vlen
            headers.append((STATIC_TABLE[idx], val))
        elif first < len(STATIC_TABLE) and i + 3 <= size and payload[i+1] == 0:
            idx = first
            i += 1
            vlen = struct.unpack(">H", payload[i:i+2])[0]
            i += 2
            val = payload[i:i+vlen].decode("utf-8", errors="replace")
            i += vlen
            headers.append((STATIC_TABLE[idx], val))
        else:
            nlen = struct.unpack(">H", payload[i:i+2])[0]
            i += 2
            name = payload[i:i+nlen].decode("utf-8", errors="replace")
            i += nlen
            vlen = struct.unpack(">H", payload[i:i+2])[0]
            i += 2
            val = payload[i:i+vlen].decode("utf-8", errors="replace")
            i += vlen
            headers.append((name, val))
    return headers

def read_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)

def read_frame(sock):
    hdr_bytes = read_exact(sock, 9)
    length, ftype, flags, stream_id = parse_frame_header(hdr_bytes)
    payload = read_exact(sock, length) if length > 0 else b""
    return length, ftype, flags, stream_id, payload

def run_tests():
    print("==================================================")
    print(" Running Binary HTTP Protocol Verification Suite")
    print("==================================================")

    # Start bserve in background
    proc = subprocess.Popen(["./bserve", ROOT_DIR, str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Wait until port is ready
    bound = False
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.1):
                bound = True
                break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    assert bound, f"bserve failed to bind to port {PORT}"

    try:
        # Test 1: bcurl CLI test fetching index.html
        print("[TEST 1] Testing bcurl CLI fetching index.html...")
        res = subprocess.run(["./bcurl", f"http://127.0.0.1:{PORT}/index.html"], capture_output=True, text=True)
        assert res.returncode == 0, f"bcurl failed with code {res.returncode}: {res.stderr}"
        assert "Welcome to bserve" in res.stdout, f"Unexpected body: {res.stdout}"
        print("  --> PASSED: 200 OK received with expected body")

        # Test 2: bcurl CLI fetching /hello.txt with -i (include headers)
        print("[TEST 2] Testing bcurl CLI with -i flag...")
        res = subprocess.run(["./bcurl", "-i", f"http://127.0.0.1:{PORT}/hello.txt"], capture_output=True, text=True)
        assert res.returncode == 0
        assert ":status: 200" in res.stdout
        assert "content-type: text/plain" in res.stdout
        assert "Hello from bserve binary protocol!" in res.stdout
        print("  --> PASSED: Headers and body formatted correctly")

        # Test 3: bcurl CLI fetching non-existent file -> 404
        print("[TEST 3] Testing bcurl 404 Not Found handling...")
        res = subprocess.run(["./bcurl", f"http://127.0.0.1:{PORT}/missing.txt"], capture_output=True, text=True)
        assert res.returncode != 0
        assert "404 Not Found" in res.stdout
        print("  --> PASSED: 404 Not Found properly returned")

        # Test 4: Directory traversal prevention (/../../secret.txt and /../secret.txt)
        print("[TEST 4] Testing Directory Traversal Prevention...")
        for malicious_path in ["/../../secret.txt", "/../secret.txt", "/..%2fsecret.txt", "/subdir/../../secret.txt"]:
            res = subprocess.run(["./bcurl", f"http://127.0.0.1:{PORT}{malicious_path}"], capture_output=True, text=True)
            assert res.returncode != 0, f"Traversal attack was not blocked for {malicious_path}!"
            assert "SUPER_SECRET_DATA" not in res.stdout, f"Information leaked for {malicious_path}!"
        print("  --> PASSED: Traversal attacks strictly contained within root")

        # Test 5: Persistent Keep-Alive socket test (5 consecutive requests on 1 TCP socket)
        print("[TEST 5] Testing Persistent Connection Loop (Keep-Alive)...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", PORT))

        paths_to_test = ["/hello.txt", "/style.css", "/index.html", "/hello.txt", "/index.html"]
        for idx, p in enumerate(paths_to_test):
            stream_id = 1 + idx * 2
            hdrs = [(":method", "GET"), (":path", p), ("host", f"localhost:{PORT}"), ("user-agent", "keep-alive-test")]
            h_payload = encode_headers(hdrs)
            req_frame = serialize_frame(len(h_payload), TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, stream_id, h_payload)
            sock.sendall(req_frame)

            # Read response frames
            got_stream_end = False
            resp_status = None
            body_chunks = []
            while not got_stream_end:
                length, ftype, flags, s_id, payload = read_frame(sock)
                assert s_id == stream_id, f"Stream ID mismatch: expected {stream_id}, got {s_id}"
                if ftype == TYPE_HEADERS:
                    decoded = dict(decode_headers(payload))
                    resp_status = decoded.get(":status")
                elif ftype == TYPE_DATA:
                    body_chunks.append(payload)
                if flags & FLAG_END_STREAM:
                    got_stream_end = True

            assert resp_status == "200", f"Expected 200 for {p}, got {resp_status}"
            body = b"".join(body_chunks).decode("utf-8")
            assert len(body) > 0, f"Empty body for {p}"

        sock.close()
        print("  --> PASSED: 5 sequential requests served successfully over single persistent connection")

        # Test 6: Extensibility & Unknown Frame Rule
        print("[TEST 6] Testing Extensibility & Unknown Frame Discard Rule...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", PORT))

        # Inject Unknown Frame Type 0x77 with 20 bytes of dummy payload
        unk_payload = b"UNKNOWN_FRAME_DATA_!"
        unk_frame = serialize_frame(len(unk_payload), 0x77, 0x00, 0, unk_payload)
        sock.sendall(unk_frame)

        # Inject another Unknown Frame Type 0xFE with 40 bytes
        unk_payload2 = b"ANOTHER_UNKNOWN_FRAME_EXTENSIBILITY_TEST"
        unk_frame2 = serialize_frame(len(unk_payload2), 0xFE, 0x00, 0, unk_payload2)
        sock.sendall(unk_frame2)

        # Immediately send valid HEADERS frame on stream 1
        hdrs = [(":method", "GET"), (":path", "/hello.txt"), ("host", f"localhost:{PORT}")]
        h_payload = encode_headers(hdrs)
        req_frame = serialize_frame(len(h_payload), TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, h_payload)
        sock.sendall(req_frame)

        # Receiver MUST discard unknown frames cleanly and return 200 for stream 1!
        got_stream_end = False
        resp_status = None
        body_chunks = []
        while not got_stream_end:
            length, ftype, flags, s_id, payload = read_frame(sock)
            if ftype == TYPE_HEADERS:
                decoded = dict(decode_headers(payload))
                resp_status = decoded.get(":status")
            elif ftype == TYPE_DATA:
                body_chunks.append(payload)
            if flags & FLAG_END_STREAM:
                got_stream_end = True

        assert resp_status == "200", f"Expected 200 after unknown frames, got {resp_status}"
        assert b"Hello from bserve" in b"".join(body_chunks)
        sock.close()
        print("  --> PASSED: Unknown frames discarded cleanly without breaking connection or stream")

        # Test 7: Binary file transfer integrity (64KB test.bin)
        print("[TEST 7] Testing Binary Transfer Integrity (64KB binary file)...")
        res = subprocess.run(["./bcurl", "-o", "downloaded.bin", f"http://127.0.0.1:{PORT}/test.bin"], capture_output=True)
        assert res.returncode == 0
        orig_data = open("www/test.bin", "rb").read()
        down_data = open("downloaded.bin", "rb").read()
        assert orig_data == down_data, f"Binary data mismatch: {len(orig_data)} vs {len(down_data)}"
        os.remove("downloaded.bin")
        print("  --> PASSED: 65,536 bytes transferred with 100% byte-exact integrity")

        # Test 8: Malformed frame / parse failure handling
        print("[TEST 8] Testing Malformed Frame Handling (400 Bad Request)...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", PORT))
        # Send HEADERS with invalid garbage payload (not valid header encoding)
        bad_payload = b"\x00\x00\x00\xFF\xAA\xBB"
        bad_frame = serialize_frame(len(bad_payload), TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1, bad_payload)
        sock.sendall(bad_frame)
        length, ftype, flags, s_id, payload = read_frame(sock)
        assert ftype == TYPE_HEADERS
        decoded = dict(decode_headers(payload))
        assert decoded.get(":status") == "400", f"Expected 400 for malformed payload, got {decoded.get(':status')}"
        sock.close()
        print("  --> PASSED: Server gracefully returned 400 Bad Request")

        print("==================================================")
        print(" ALL TESTS PASSED SUCCESSFULLY! ")
        print("==================================================")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

if __name__ == "__main__":
    run_tests()
