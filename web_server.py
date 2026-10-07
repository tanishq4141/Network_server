#!/usr/bin/env python3
import http.server
import socketserver
import json
import socket
import struct
import subprocess
import time
import os
import mimetypes

UI_PORT = 8080
BSERVE_PORT = 9000
ROOT_DIR = os.path.abspath("./www")
UI_DIR = os.path.abspath("./ui")

STATIC_TABLE = [
    ":method",         # 0
    ":path",           # 1
    ":status",         # 2
    "content-type",    # 3
    "content-length",  # 4
    "server",          # 5
    "user-agent",      # 6
    "host",            # 7
    "date",            # 8
    "connection"       # 9
]

# Ensure bserve is compiled and running
def ensure_bserve_running():
    try:
        with socket.create_connection(("127.0.0.1", BSERVE_PORT), timeout=0.2):
            return None # Already running
    except (ConnectionRefusedError, OSError):
        pass

    # Build if needed
    if not os.path.exists("./bserve"):
        subprocess.run(["make"], check=True)

    print(f"[*] Launching bserve on port {BSERVE_PORT}...")
    proc = subprocess.Popen(["./bserve", ROOT_DIR, str(BSERVE_PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    return proc

def read_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf.extend(chunk)
    return bytes(buf)

def serialize_frame(length, ftype, flags, stream_id, payload=b""):
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

def annotate_header_frame(hdr_bytes, payload_bytes):
    length, ftype, flags, stream_id = parse_frame_header(hdr_bytes)
    annotated = []
    
    # 9-byte header
    annotated.append({"hex": f"{hdr_bytes[0]:02x}", "class": "f-length", "desc": f"Length Byte 0 (Payload: {length}B)"})
    annotated.append({"hex": f"{hdr_bytes[1]:02x}", "class": "f-length", "desc": f"Length Byte 1 (Payload: {length}B)"})
    annotated.append({"hex": f"{hdr_bytes[2]:02x}", "class": "f-length", "desc": f"Length Byte 2 (Payload: {length}B)"})
    
    type_name = "HEADERS (0x01)" if ftype == 1 else "DATA (0x02)" if ftype == 2 else f"TYPE 0x{ftype:02x}"
    annotated.append({"hex": f"{hdr_bytes[3]:02x}", "class": "f-type", "desc": f"Frame Type: {type_name}"})
    
    flag_names = []
    if flags & 0x01: flag_names.append("END_STREAM (0x01)")
    if flags & 0x02: flag_names.append("END_HEADERS (0x02)")
    flag_desc = " | ".join(flag_names) if flag_names else "NONE (0x00)"
    annotated.append({"hex": f"{hdr_bytes[4]:02x}", "class": "f-flags", "desc": f"Flags: {flag_desc}"})
    
    annotated.append({"hex": f"{hdr_bytes[5]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 0] = {stream_id}"})
    annotated.append({"hex": f"{hdr_bytes[6]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 1]"})
    annotated.append({"hex": f"{hdr_bytes[7]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 2]"})
    annotated.append({"hex": f"{hdr_bytes[8]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 3]"})
    
    # Annotate payload headers
    i = 0
    size = len(payload_bytes)
    while i < size:
        first = payload_bytes[i]
        if first & 0x80:
            idx = first & 0x7F
            name = STATIC_TABLE[idx] if idx < len(STATIC_TABLE) else f"Index {idx}"
            annotated.append({"hex": f"{first:02x}", "class": "f-index", "desc": f"HPACK Static Index [{idx}] = '{name}'"})
            i += 1
            vlen = struct.unpack(">H", payload_bytes[i:i+2])[0]
            annotated.append({"hex": f"{payload_bytes[i]:02x}", "class": "f-vallen", "desc": f"Value Length High Byte = {vlen}"})
            annotated.append({"hex": f"{payload_bytes[i+1]:02x}", "class": "f-vallen", "desc": f"Value Length Low Byte = {vlen}"})
            i += 2
            val_chars = payload_bytes[i:i+vlen]
            for b in val_chars:
                ch = chr(b) if 32 <= b <= 126 else "."
                annotated.append({"hex": f"{b:02x}", "class": "f-payload", "desc": f"Val Char '{ch}' for '{name}'"})
            i += vlen
        elif first < len(STATIC_TABLE) and i + 3 <= size and payload_bytes[i+1] == 0:
            idx = first
            name = STATIC_TABLE[idx]
            annotated.append({"hex": f"{first:02x}", "class": "f-index", "desc": f"HPACK Static Index [{idx}] = '{name}'"})
            i += 1
            vlen = struct.unpack(">H", payload_bytes[i:i+2])[0]
            annotated.append({"hex": f"{payload_bytes[i]:02x}", "class": "f-vallen", "desc": f"Value Length High Byte = {vlen}"})
            annotated.append({"hex": f"{payload_bytes[i+1]:02x}", "class": "f-vallen", "desc": f"Value Length Low Byte = {vlen}"})
            i += 2
            val_chars = payload_bytes[i:i+vlen]
            for b in val_chars:
                ch = chr(b) if 32 <= b <= 126 else "."
                annotated.append({"hex": f"{b:02x}", "class": "f-payload", "desc": f"Val Char '{ch}' for '{name}'"})
            i += vlen
        else:
            nlen = struct.unpack(">H", payload_bytes[i:i+2])[0]
            annotated.append({"hex": f"{payload_bytes[i]:02x}", "class": "f-vallen", "desc": f"Literal Name Length High = {nlen}"})
            annotated.append({"hex": f"{payload_bytes[i+1]:02x}", "class": "f-vallen", "desc": f"Literal Name Length Low = {nlen}"})
            i += 2
            name_chars = payload_bytes[i:i+nlen]
            name_str = name_chars.decode("utf-8", errors="replace")
            for b in name_chars:
                ch = chr(b) if 32 <= b <= 126 else "."
                annotated.append({"hex": f"{b:02x}", "class": "f-payload", "desc": f"Literal Name Char '{ch}'"})
            i += nlen
            vlen = struct.unpack(">H", payload_bytes[i:i+2])[0]
            annotated.append({"hex": f"{payload_bytes[i]:02x}", "class": "f-vallen", "desc": f"Value Length High = {vlen}"})
            annotated.append({"hex": f"{payload_bytes[i+1]:02x}", "class": "f-vallen", "desc": f"Value Length Low = {vlen}"})
            i += 2
            val_chars = payload_bytes[i:i+vlen]
            for b in val_chars:
                ch = chr(b) if 32 <= b <= 126 else "."
                annotated.append({"hex": f"{b:02x}", "class": "f-payload", "desc": f"Val Char '{ch}' for '{name_str}'"})
            i += vlen
            
    return annotated

def annotate_data_frame(hdr_bytes, payload_bytes):
    length, ftype, flags, stream_id = parse_frame_header(hdr_bytes)
    annotated = []
    
    annotated.append({"hex": f"{hdr_bytes[0]:02x}", "class": "f-length", "desc": f"Length Byte 0 (Payload: {length}B)"})
    annotated.append({"hex": f"{hdr_bytes[1]:02x}", "class": "f-length", "desc": f"Length Byte 1 (Payload: {length}B)"})
    annotated.append({"hex": f"{hdr_bytes[2]:02x}", "class": "f-length", "desc": f"Length Byte 2 (Payload: {length}B)"})
    annotated.append({"hex": f"{hdr_bytes[3]:02x}", "class": "f-type", "desc": "Frame Type: 0x02 (DATA)"})
    
    flag_desc = "END_STREAM (0x01)" if flags & 0x01 else "NONE (0x00)"
    annotated.append({"hex": f"{hdr_bytes[4]:02x}", "class": "f-flags", "desc": f"Flags: {flag_desc}"})
    
    annotated.append({"hex": f"{hdr_bytes[5]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 0] = {stream_id}"})
    annotated.append({"hex": f"{hdr_bytes[6]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 1]"})
    annotated.append({"hex": f"{hdr_bytes[7]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 2]"})
    annotated.append({"hex": f"{hdr_bytes[8]:02x}", "class": "f-stream", "desc": f"Stream ID [Byte 3]"})
    
    for b in payload_bytes:
        ch = chr(b) if 32 <= b <= 126 else "."
        annotated.append({"hex": f"{b:02x}", "class": "f-payload", "desc": f"Data Payload Byte: '{ch}'"})
        
    return annotated

class WorkbenchHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def do_POST(self):
        if self.path == "/api/send":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            req_data = json.loads(body.decode("utf-8"))
            
            method = req_data.get("method", "GET")
            path = req_data.get("path", "/hello.txt")
            stream_id = req_data.get("stream_id", 1)
            inject_unknown = req_data.get("inject_unknown", False)
            headers_list = req_data.get("headers", [])
            
            # Encode headers payload
            payload_buf = bytearray()
            for h in headers_list:
                name = h["name"]
                val = h["value"]
                if name in STATIC_TABLE:
                    idx = STATIC_TABLE.index(name)
                    payload_buf.append(idx)
                    v_bytes = val.encode("utf-8")
                    payload_buf.extend(struct.pack(">H", len(v_bytes)))
                    payload_buf.extend(v_bytes)
                else:
                    n_bytes = name.encode("utf-8")
                    v_bytes = val.encode("utf-8")
                    payload_buf.extend(struct.pack(">H", len(n_bytes)))
                    payload_buf.extend(n_bytes)
                    payload_buf.extend(struct.pack(">H", len(v_bytes)))
                    payload_buf.extend(v_bytes)

            req_hdr_bytes = bytearray(9)
            req_len = len(payload_buf)
            req_hdr_bytes[0] = (req_len >> 16) & 0xFF
            req_hdr_bytes[1] = (req_len >> 8) & 0xFF
            req_hdr_bytes[2] = req_len & 0xFF
            req_hdr_bytes[3] = 0x01 # HEADERS
            req_hdr_bytes[4] = 0x03 # END_STREAM | END_HEADERS
            req_hdr_bytes[5] = (stream_id >> 24) & 0x7F
            req_hdr_bytes[6] = (stream_id >> 16) & 0xFF
            req_hdr_bytes[7] = (stream_id >> 8) & 0xFF
            req_hdr_bytes[8] = stream_id & 0xFF

            req_annotated = annotate_header_frame(req_hdr_bytes, payload_buf)

            # Transmit over TCP to bserve
            t0 = time.perf_counter_ns()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", BSERVE_PORT))
            
            if inject_unknown:
                unk_payload = b"EXTENSIBILITY_TEST_PAYLOAD"
                unk_frame = serialize_frame(len(unk_payload), 0x99, 0x00, 0, unk_payload)
                sock.sendall(unk_frame)
                
            sock.sendall(bytes(req_hdr_bytes) + bytes(payload_buf))
            
            # Read response frames
            resp_headers_annotated = []
            resp_data_annotated = []
            resp_headers_list = []
            body_chunks = []
            resp_status = 200
            resp_mime = "text/plain"
            stream_ended = False

            while not stream_ended:
                hdr_raw = read_exact(sock, 9)
                length, ftype, flags, s_id = parse_frame_header(hdr_raw)
                
                # Unknown frame discard
                if ftype not in (1, 2, 3, 4):
                    if length > 0:
                        _ = read_exact(sock, length)
                    continue

                payload = read_exact(sock, length) if length > 0 else b""

                if ftype == 1: # HEADERS
                    resp_headers_annotated = annotate_header_frame(hdr_raw, payload)
                    # Decode headers
                    i = 0
                    while i < len(payload):
                        first = payload[i]
                        if first & 0x80:
                            idx = first & 0x7F
                            i += 1
                            vlen = struct.unpack(">H", payload[i:i+2])[0]
                            i += 2
                            vstr = payload[i:i+vlen].decode("utf-8", errors="replace")
                            i += vlen
                            resp_headers_list.append({"name": STATIC_TABLE[idx], "value": vstr})
                        elif first < len(STATIC_TABLE) and i + 3 <= len(payload) and payload[i+1] == 0:
                            idx = first
                            i += 1
                            vlen = struct.unpack(">H", payload[i:i+2])[0]
                            i += 2
                            vstr = payload[i:i+vlen].decode("utf-8", errors="replace")
                            i += vlen
                            resp_headers_list.append({"name": STATIC_TABLE[idx], "value": vstr})
                        else:
                            nlen = struct.unpack(">H", payload[i:i+2])[0]
                            i += 2
                            nstr = payload[i:i+nlen].decode("utf-8", errors="replace")
                            i += nlen
                            vlen = struct.unpack(">H", payload[i:i+2])[0]
                            i += 2
                            vstr = payload[i:i+vlen].decode("utf-8", errors="replace")
                            i += vlen
                            resp_headers_list.append({"name": nstr, "value": vstr})
                            
                    for h in resp_headers_list:
                        if h["name"] == ":status": resp_status = int(h["value"])
                        if h["name"] == "content-type": resp_mime = h["value"]
                        
                elif ftype == 2: # DATA
                    resp_data_annotated = annotate_data_frame(hdr_raw, payload)
                    body_chunks.append(payload)

                if flags & 0x01: # END_STREAM
                    stream_ended = True

            t1 = time.perf_counter_ns()
            latency_us = max(1, (t1 - t0) // 1000)
            
            # Send GOAWAY and close
            goaway_frame = serialize_frame(8, 0x04, 0x00, 0, struct.pack(">II", stream_id, 0))
            try:
                sock.sendall(goaway_frame)
            except: pass
            sock.close()

            full_body = b"".join(body_chunks).decode("utf-8", errors="replace")
            
            response_json = {
                "status": resp_status,
                "status_text": "OK" if resp_status == 200 else "Not Found" if resp_status == 404 else "Error",
                "stream_id": stream_id,
                "latency_us": latency_us,
                "mime": resp_mime,
                "body_size": len(full_body),
                "body_text": full_body,
                "req_headers": headers_list,
                "resp_headers": resp_headers_list,
                "req_frame": {
                    "total_bytes": len(req_annotated),
                    "payload_bytes": req_len,
                    "bytes": req_annotated
                },
                "resp_headers_frame": {
                    "total_bytes": len(resp_headers_annotated),
                    "payload_bytes": len(resp_headers_annotated) - 9,
                    "bytes": resp_headers_annotated
                },
                "resp_data_frame": {
                    "total_bytes": len(resp_data_annotated),
                    "payload_bytes": len(resp_data_annotated) - 9,
                    "bytes": resp_data_annotated
                } if resp_data_annotated else None
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response_json).encode("utf-8"))

def start_server():
    server_proc = ensure_bserve_running()
    print(f"==========================================================")
    print(f" bHTTP Interactive Workbench running at:")
    print(f" http://localhost:{UI_PORT}")
    print(f"==========================================================")
    
    # Allow port reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", UI_PORT), WorkbenchHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down UI server...")
        finally:
            if server_proc:
                server_proc.terminate()

if __name__ == "__main__":
    start_server()
