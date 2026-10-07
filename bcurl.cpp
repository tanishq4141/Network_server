#include "protocol.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <optional>
#include <sstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

namespace {

struct CliOptions {
    std::string host = "127.0.0.1";
    int port = 9000;
    std::string path = "/";
    bool verbose = false;
    bool include_headers = false;
    bool raw_hex = false;
    bool send_unknown = false;
    std::string output_file;
};

// URL parser: supports http://host:port/path, host:port/path, or separate args
bool parse_url_string(const std::string& url_str, CliOptions& opts) {
    std::string s = url_str;
    if (s.rfind("http://", 0) == 0) {
        s = s.substr(7);
    } else if (s.rfind("bhttp://", 0) == 0) {
        s = s.substr(8);
    }

    size_t slash_pos = s.find('/');
    std::string host_port;
    if (slash_pos != std::string::npos) {
        host_port = s.substr(0, slash_pos);
        opts.path = s.substr(slash_pos);
    } else {
        host_port = s;
        opts.path = "/";
    }

    size_t colon_pos = host_port.find(':');
    if (colon_pos != std::string::npos) {
        opts.host = host_port.substr(0, colon_pos);
        try {
            opts.port = std::stoi(host_port.substr(colon_pos + 1));
        } catch (...) {
            return false;
        }
    } else {
        opts.host = host_port;
        opts.port = 80;
    }

    if (opts.host.empty()) opts.host = "127.0.0.1";
    if (opts.path.empty()) opts.path = "/";
    return true;
}

bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = ::read(fd, buf + total, n - total);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

bool write_exact(int fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = ::write(fd, buf + total, n - total);
        if (w <= 0) return false;
        total += static_cast<size_t>(w);
    }
    return true;
}

void print_hex_field(std::string_view label, const uint8_t* data, size_t len) {
    std::cerr << "  " << label << " (" << len << "B): ";
    for (size_t i = 0; i < len; ++i) {
        std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
    }
    std::cerr << std::dec << "\n";
}

} // namespace

int main(int argc, char* argv[]) {
    CliOptions opts;
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-i" || arg == "--include") {
            opts.include_headers = true;
        } else if (arg == "--raw-hex") {
            opts.raw_hex = true;
        } else if (arg == "--send-unknown") {
            opts.send_unknown = true;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                opts.output_file = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an argument\n";
                return 1;
            }
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options] <url>\n";
            std::cout << "       " << argv[0] << " [options] <host> <port> <path>\n\n";
            std::cout << "Options:\n";
            std::cout << "  -v, --verbose       Show verbose frame transmission logs\n";
            std::cout << "  -i, --include       Include HTTP response headers in output\n";
            std::cout << "  -o, --output <file> Write response body to file\n";
            std::cout << "  --raw-hex           Dump raw hex bytes of sent and received frames\n";
            std::cout << "  --send-unknown      Send unknown frame before request to test receiver extensibility\n";
            std::cout << "  -h, --help          Show this help message\n\n";
            std::cout << "Examples:\n";
            std::cout << "  " << argv[0] << " http://127.0.0.1:9000/index.html\n";
            std::cout << "  " << argv[0] << " -v 127.0.0.1 9000 /style.css\n";
            return 0;
        } else {
            positional.push_back(arg);
        }
    }

    if (positional.empty()) {
        std::cerr << "Usage: " << argv[0] << " [options] <url>\n";
        std::cerr << "Try '" << argv[0] << " --help' for more information.\n";
        return 1;
    }

    if (positional.size() == 1) {
        if (!parse_url_string(positional[0], opts)) {
            std::cerr << "Error: Could not parse URL: " << positional[0] << std::endl;
            return 1;
        }
    } else if (positional.size() >= 3) {
        opts.host = positional[0];
        try {
            opts.port = std::stoi(positional[1]);
        } catch (...) {
            std::cerr << "Error: Invalid port: " << positional[1] << std::endl;
            return 1;
        }
        opts.path = positional[2];
    } else {
        std::cerr << "Error: Ambiguous arguments. Provide single URL or <host> <port> <path>.\n";
        return 1;
    }

    if (opts.verbose) {
        std::cerr << "* Connecting to " << opts.host << " port " << opts.port << "...\n";
    }

    // Resolve host
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;

    std::string port_str = std::to_string(opts.port);
    int err = ::getaddrinfo(opts.host.c_str(), port_str.c_str(), &hints, &res);
    if (err != 0) {
        std::cerr << "Error: getaddrinfo failed: " << gai_strerror(err) << std::endl;
        return 1;
    }

    int sock_fd = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock_fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock_fd < 0) continue;

        if (::connect(sock_fd, p->ai_addr, p->ai_addrlen) == 0) {
            break; // Successfully connected
        }
        ::close(sock_fd);
        sock_fd = -1;
    }
    ::freeaddrinfo(res);

    if (sock_fd < 0) {
        std::cerr << "Error: Failed to connect to " << opts.host << ":" << opts.port << std::endl;
        return 1;
    }

    // Set TCP_NODELAY
    int nodelay = 1;
    ::setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    if (opts.verbose) {
        std::cerr << "* Connected successfully.\n";
    }

    // (Optional) Test receiver extensibility by sending unknown frame first
    if (opts.send_unknown) {
        std::string unk_payload = "EXTENSIBILITY_TEST_PAYLOAD";
        bproto::FrameHeader unk_hdr;
        unk_hdr.length = static_cast<uint32_t>(unk_payload.size());
        unk_hdr.type = 0x99; // Unknown Frame Type
        unk_hdr.flags = 0x00;
        unk_hdr.stream_id = 0;

        auto unk_hdr_bytes = bproto::serialize_frame_header(unk_hdr);
        write_exact(sock_fd, unk_hdr_bytes.data(), unk_hdr_bytes.size());
        write_exact(sock_fd, reinterpret_cast<const uint8_t*>(unk_payload.data()), unk_payload.size());

        if (opts.verbose) {
            std::cerr << "> [OUT] Sent UNKNOWN frame (Type 0x99, Length " << unk_payload.size() << "B)\n";
        }
    }

    // 1. Prepare HEADERS frame for GET request
    uint32_t stream_id = 1; // Client-initiated stream ID (odd)
    std::vector<bproto::HeaderField> req_headers = {
        {":method", "GET"},
        {":path", opts.path},
        {"host", opts.host + ":" + std::to_string(opts.port)},
        {"user-agent", "bcurl/1.0"}
    };

    std::vector<uint8_t> encoded_headers = bproto::encode_headers(req_headers);

    bproto::FrameHeader req_hdr;
    req_hdr.length = static_cast<uint32_t>(encoded_headers.size());
    req_hdr.type = static_cast<uint8_t>(bproto::FrameType::HEADERS);
    // GET request has no body, so set END_STREAM and END_HEADERS
    req_hdr.flags = bproto::Flags::END_STREAM | bproto::Flags::END_HEADERS;
    req_hdr.stream_id = stream_id;

    auto req_hdr_bytes = bproto::serialize_frame_header(req_hdr);

    if (opts.verbose) {
        std::cerr << "> [OUT] HEADERS Frame on Stream " << stream_id << " (Payload " << req_hdr.length << " bytes)\n";
        for (const auto& h : req_headers) {
            std::cerr << ">   " << h.name << ": " << h.value << "\n";
        }
    }

    if (opts.raw_hex) {
        std::cerr << "=== REQUEST FRAME HEX DUMP ===\n";
        print_hex_field("Header [Length(3) Type(1) Flags(1) StreamID(4)]", req_hdr_bytes.data(), req_hdr_bytes.size());
        print_hex_field("Payload (Encoded Headers)", encoded_headers.data(), encoded_headers.size());
        std::cerr << "==============================\n";
    }

    // Send request
    if (!write_exact(sock_fd, req_hdr_bytes.data(), req_hdr_bytes.size()) ||
        !write_exact(sock_fd, encoded_headers.data(), encoded_headers.size())) {
        std::cerr << "Error: Failed to send request frame\n";
        ::close(sock_fd);
        return 1;
    }

    // 2. Read response frames
    std::string response_status;
    std::vector<bproto::HeaderField> response_headers;
    std::vector<uint8_t> response_body;
    bool stream_ended = false;

    while (!stream_ended) {
        uint8_t hdr_raw[bproto::FRAME_HEADER_SIZE];
        if (!read_exact(sock_fd, hdr_raw, bproto::FRAME_HEADER_SIZE)) {
            std::cerr << "Error: Server closed connection prematurely\n";
            ::close(sock_fd);
            return 1;
        }

        bproto::FrameHeader resp_hdr = bproto::deserialize_frame_header(hdr_raw);

        if (opts.verbose) {
            std::cerr << "< [IN] " << resp_hdr.type_name() << " Frame (Stream " << resp_hdr.stream_id 
                      << ", Length " << resp_hdr.length << "B, Flags 0x" 
                      << std::hex << static_cast<int>(resp_hdr.flags) << std::dec << ")\n";
        }

        // ====================================================================
        // Extensibility Rule: Unknown frames must be read and cleanly discarded
        // ====================================================================
        auto ftype = static_cast<bproto::FrameType>(resp_hdr.type);
        if (ftype != bproto::FrameType::HEADERS &&
            ftype != bproto::FrameType::DATA &&
            ftype != bproto::FrameType::SETTINGS &&
            ftype != bproto::FrameType::GOAWAY) {
            
            if (opts.verbose) {
                std::cerr << "< [UNKNOWN FRAME 0x" << std::hex << static_cast<int>(resp_hdr.type) << std::dec 
                          << "] Discarding " << resp_hdr.length << " bytes\n";
            }
            std::vector<uint8_t> discard(resp_hdr.length);
            if (resp_hdr.length > 0) {
                if (!read_exact(sock_fd, discard.data(), resp_hdr.length)) {
                    break;
                }
            }
            continue;
        }

        std::vector<uint8_t> payload(resp_hdr.length);
        if (resp_hdr.length > 0) {
            if (!read_exact(sock_fd, payload.data(), resp_hdr.length)) {
                std::cerr << "Error: Failed to read frame payload\n";
                ::close(sock_fd);
                return 1;
            }
        }

        if (opts.raw_hex) {
            std::cerr << "=== RESPONSE FRAME (" << resp_hdr.type_name() << ") HEX DUMP ===\n";
            print_hex_field("Header [Length(3) Type(1) Flags(1) StreamID(4)]", hdr_raw, sizeof(hdr_raw));
            if (!payload.empty()) {
                print_hex_field("Payload", payload.data(), payload.size());
            }
            std::cerr << "========================================\n";
        }

        if (ftype == bproto::FrameType::HEADERS) {
            try {
                response_headers = bproto::decode_headers(payload.data(), payload.size());
                for (const auto& h : response_headers) {
                    if (h.name == ":status") {
                        response_status = h.value;
                    }
                    if (opts.verbose) {
                        std::cerr << "<   " << h.name << ": " << h.value << "\n";
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Failed to decode response headers: " << e.what() << "\n";
            }
        } else if (ftype == bproto::FrameType::DATA) {
            response_body.insert(response_body.end(), payload.begin(), payload.end());
        } else if (ftype == bproto::FrameType::GOAWAY) {
            if (opts.verbose) {
                std::cerr << "* GOAWAY received from server.\n";
            }
            break;
        }

        if (resp_hdr.has_flag(bproto::Flags::END_STREAM)) {
            stream_ended = true;
        }
    }

    // Gracefully send GOAWAY
    bproto::FrameHeader goaway_hdr;
    goaway_hdr.length = 8;
    goaway_hdr.type = static_cast<uint8_t>(bproto::FrameType::GOAWAY);
    goaway_hdr.flags = 0;
    goaway_hdr.stream_id = 0;
    std::array<uint8_t, 8> goaway_payload{
        0x00, 0x00, 0x00, 0x01, // Last-Stream-ID = 1
        0x00, 0x00, 0x00, 0x00  // NO_ERROR
    };
    auto goaway_bytes = bproto::serialize_frame_header(goaway_hdr);
    write_exact(sock_fd, goaway_bytes.data(), goaway_bytes.size());
    write_exact(sock_fd, goaway_payload.data(), goaway_payload.size());

    ::close(sock_fd);

    // Print headers if requested (-i)
    if (opts.include_headers) {
        std::cout << "HTTP/2-Binary " << response_status << "\n";
        for (const auto& h : response_headers) {
            std::cout << h.name << ": " << h.value << "\n";
        }
        std::cout << "\n";
    }

    // Output body
    if (!opts.output_file.empty()) {
        std::ofstream out(opts.output_file, std::ios::binary);
        if (!out) {
            std::cerr << "Error: Cannot open output file: " << opts.output_file << "\n";
            return 1;
        }
        out.write(reinterpret_cast<const char*>(response_body.data()), response_body.size());
        if (opts.verbose) {
            std::cerr << "* Saved " << response_body.size() << " bytes to " << opts.output_file << "\n";
        }
    } else {
        std::cout.write(reinterpret_cast<const char*>(response_body.data()), response_body.size());
        std::cout.flush();
    }

    return (response_status == "200") ? 0 : 2;
}
