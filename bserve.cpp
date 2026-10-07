#include "protocol.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <cstring>
#include <csignal>
#include <atomic>
#include <sstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

namespace fs = std::filesystem;

namespace {

std::atomic<bool> g_running{true};

void sigint_handler(int) {
    g_running = false;
}

// Generate RFC 1123 HTTP Date string
std::string get_rfc1123_date() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    char buf[128];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
    return std::string(buf);
}

// URL-decode helper to handle %20, %2e, etc.
std::string url_decode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            char hex[3] = {in[i + 1], in[i + 2], '\0'};
            char* end = nullptr;
            long val = std::strtol(hex, &end, 16);
            if (end == hex + 2) {
                out.push_back(static_cast<char>(val));
                i += 2;
                continue;
            }
        } else if (in[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(in[i]);
    }
    return out;
}

// Read exactly n bytes from a socket
bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = ::read(fd, buf + total, n - total);
        if (r <= 0) {
            return false; // Connection closed or error
        }
        total += static_cast<size_t>(r);
    }
    return true;
}

// Write exactly n bytes to a socket
bool write_exact(int fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = ::write(fd, buf + total, n - total);
        if (w <= 0) {
            return false;
        }
        total += static_cast<size_t>(w);
    }
    return true;
}

// Send a frame over socket
bool send_frame(int fd, const bproto::FrameHeader& header, const uint8_t* payload) {
    auto hdr_bytes = bproto::serialize_frame_header(header);
    if (!write_exact(fd, hdr_bytes.data(), hdr_bytes.size())) {
        return false;
    }
    if (header.length > 0 && payload != nullptr) {
        if (!write_exact(fd, payload, header.length)) {
            return false;
        }
    }
    return true;
}

// Send HEADERS response frame
bool send_headers_response(int fd, uint32_t stream_id, const std::vector<bproto::HeaderField>& headers, bool end_stream = false) {
    std::vector<uint8_t> payload = bproto::encode_headers(headers);
    bproto::FrameHeader h;
    h.length = static_cast<uint32_t>(payload.size());
    h.type = static_cast<uint8_t>(bproto::FrameType::HEADERS);
    h.flags = bproto::Flags::END_HEADERS | (end_stream ? bproto::Flags::END_STREAM : 0);
    h.stream_id = stream_id;
    return send_frame(fd, h, payload.data());
}

// Send DATA frame
bool send_data_response(int fd, uint32_t stream_id, const uint8_t* data, size_t len, bool end_stream = true) {
    bproto::FrameHeader h;
    h.length = static_cast<uint32_t>(len);
    h.type = static_cast<uint8_t>(bproto::FrameType::DATA);
    h.flags = end_stream ? bproto::Flags::END_STREAM : 0;
    h.stream_id = stream_id;
    return send_frame(fd, h, data);
}

// Send 400 Bad Request
void send_400(int fd, uint32_t stream_id, std::string_view msg = "400 Bad Request\n") {
    std::vector<bproto::HeaderField> headers = {
        {":status", "400"},
        {"content-type", "text/plain; charset=utf-8"},
        {"content-length", std::to_string(msg.size())},
        {"server", "bserve/1.0"},
        {"date", get_rfc1123_date()},
        {"connection", "keep-alive"}
    };
    send_headers_response(fd, stream_id, headers, false);
    send_data_response(fd, stream_id, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), true);
}

// Send 404 Not Found
void send_404(int fd, uint32_t stream_id, std::string_view msg = "404 Not Found\n") {
    std::vector<bproto::HeaderField> headers = {
        {":status", "404"},
        {"content-type", "text/plain; charset=utf-8"},
        {"content-length", std::to_string(msg.size())},
        {"server", "bserve/1.0"},
        {"date", get_rfc1123_date()},
        {"connection", "keep-alive"}
    };
    send_headers_response(fd, stream_id, headers, false);
    send_data_response(fd, stream_id, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), true);
}

// Send 405 Method Not Allowed
void send_405(int fd, uint32_t stream_id, std::string_view msg = "405 Method Not Allowed\n") {
    std::vector<bproto::HeaderField> headers = {
        {":status", "405"},
        {"content-type", "text/plain; charset=utf-8"},
        {"content-length", std::to_string(msg.size())},
        {"server", "bserve/1.0"},
        {"date", get_rfc1123_date()},
        {"connection", "keep-alive"}
    };
    send_headers_response(fd, stream_id, headers, false);
    send_data_response(fd, stream_id, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), true);
}

// Clean and map path inside root_directory (strictly preventing traversal attacks)
std::optional<fs::path> resolve_safe_path(const fs::path& canonical_root, std::string_view raw_path) {
    // 1. Strip query string or fragment
    size_t q = raw_path.find_first_of("?#");
    if (q != std::string_view::npos) {
        raw_path = raw_path.substr(0, q);
    }

    // 2. URL decode
    std::string decoded = url_decode(raw_path);

    // 3. Must begin with '/'
    if (decoded.empty() || decoded[0] != '/') {
        return std::nullopt;
    }

    // 4. Normalize path components logically
    fs::path rel_path = fs::path(decoded).lexically_normal();

    // Check if lexical normalization tried to escape root
    std::string rel_str = rel_path.string();
    if (rel_str.find("/..") != std::string::npos || rel_str.rfind("..", 0) == 0) {
        return std::nullopt;
    }

    // Combine canonical root and relative path
    fs::path target = canonical_root;
    // Append path components skipping the leading '/'
    for (const auto& elem : rel_path) {
        if (elem == "/" || elem.empty()) continue;
        target /= elem;
    }

    // Check canonical existence
    std::error_code ec;
    fs::path canonical_target = fs::weakly_canonical(target, ec);
    if (ec) {
        return std::nullopt;
    }

    // Verify target starts with canonical_root
    std::string root_str = canonical_root.lexically_normal().string();
    std::string target_str = canonical_target.lexically_normal().string();

    if (target_str.size() < root_str.size() || target_str.compare(0, root_str.size(), root_str) != 0) {
        return std::nullopt; // Directory traversal attempt!
    }

    // If target is a directory, look for index.html
    if (fs::is_directory(canonical_target, ec)) {
        fs::path index_file = canonical_target / "index.html";
        if (fs::exists(index_file, ec) && fs::is_regular_file(index_file, ec)) {
            canonical_target = fs::canonical(index_file, ec);
        } else {
            return std::nullopt;
        }
    }

    if (!fs::exists(canonical_target, ec) || !fs::is_regular_file(canonical_target, ec)) {
        return std::nullopt;
    }

    return canonical_target;
}

// Client connection worker thread
void handle_client(int client_fd, std::string client_ip, uint16_t client_port, fs::path canonical_root) {
    std::cout << "[INFO] Accepted connection from " << client_ip << ":" << client_port << std::endl;

    // Set TCP_NODELAY for low latency
    int flag = 1;
    ::setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    // Frame processing loop (persistent keep-alive)
    while (g_running) {
        uint8_t hdr_raw[bproto::FRAME_HEADER_SIZE];
        if (!read_exact(client_fd, hdr_raw, bproto::FRAME_HEADER_SIZE)) {
            // Client closed connection or error
            break;
        }

        bproto::FrameHeader header = bproto::deserialize_frame_header(hdr_raw);

        // Check payload limit
        if (header.length > bproto::MAX_PAYLOAD_LENGTH) {
            std::cerr << "[ERROR] Frame payload length " << header.length << " exceeds 16MB limit" << std::endl;
            send_400(client_fd, header.stream_id, "400 Payload Too Large\n");
            break;
        }

        // ====================================================================
        // EXTENSIBILITY & UNKNOWN FRAME RULE:
        // A receiver encountering a Frame Type it does not recognize MUST read
        // exactly Length bytes and discard them cleanly without breaking the stream
        // or terminating the TCP connection.
        // ====================================================================
        auto frame_type = static_cast<bproto::FrameType>(header.type);
        if (frame_type != bproto::FrameType::HEADERS &&
            frame_type != bproto::FrameType::DATA &&
            frame_type != bproto::FrameType::SETTINGS &&
            frame_type != bproto::FrameType::GOAWAY) {
            
            std::cout << "[UNKNOWN FRAME] Received unknown frame type 0x" 
                      << std::hex << static_cast<int>(header.type) << std::dec
                      << " (length: " << header.length << " bytes, stream: " << header.stream_id 
                      << "). Discarding payload per protocol specification." << std::endl;
            
            // Discard exactly header.length bytes cleanly
            std::vector<uint8_t> discard_buf(header.length);
            if (header.length > 0) {
                if (!read_exact(client_fd, discard_buf.data(), header.length)) {
                    break;
                }
            }
            continue; // Keep connection open and proceed to next frame!
        }

        // Read recognized payload
        std::vector<uint8_t> payload(header.length);
        if (header.length > 0) {
            if (!read_exact(client_fd, payload.data(), header.length)) {
                break;
            }
        }

        // Handle GOAWAY frame: client gracefully terminating connection
        if (frame_type == bproto::FrameType::GOAWAY) {
            std::cout << "[INFO] GOAWAY frame received from " << client_ip << ":" << client_port << ". Closing." << std::endl;
            break;
        }

        // Handle SETTINGS frame (optional PING / connection handshake)
        if (frame_type == bproto::FrameType::SETTINGS) {
            std::cout << "[INFO] SETTINGS frame received (flags: 0x" << std::hex << static_cast<int>(header.flags) << std::dec << ")" << std::endl;
            if (!header.has_flag(bproto::Flags::ACK)) {
                // Send SETTINGS ACK
                bproto::FrameHeader ack_hdr;
                ack_hdr.length = 0;
                ack_hdr.type = static_cast<uint8_t>(bproto::FrameType::SETTINGS);
                ack_hdr.flags = bproto::Flags::ACK;
                ack_hdr.stream_id = 0;
                send_frame(client_fd, ack_hdr, nullptr);
            }
            continue;
        }

        // Handle DATA frame on request
        if (frame_type == bproto::FrameType::DATA) {
            // For simple GET requests, DATA frames from client may be unexpected or ignored
            continue;
        }

        // Handle HEADERS frame
        if (frame_type == bproto::FrameType::HEADERS) {
            std::vector<bproto::HeaderField> parsed_headers;
            try {
                parsed_headers = bproto::decode_headers(payload.data(), payload.size());
            } catch (const std::exception& ex) {
                std::cerr << "[ERROR] Failed to decode headers: " << ex.what() << std::endl;
                send_400(client_fd, header.stream_id, "400 Malformed Headers\n");
                continue;
            }

            std::string method;
            std::string path;
            for (const auto& h : parsed_headers) {
                if (h.name == ":method") method = h.value;
                else if (h.name == ":path") path = h.value;
            }

            std::cout << "[REQ] Stream " << header.stream_id << " : " << method << " " << path << std::endl;

            if (method.empty() || path.empty()) {
                send_400(client_fd, header.stream_id, "400 Missing :method or :path\n");
                continue;
            }

            if (method != "GET" && method != "HEAD") {
                send_405(client_fd, header.stream_id);
                continue;
            }

            // Path routing & traversal prevention
            auto safe_path_opt = resolve_safe_path(canonical_root, path);
            if (!safe_path_opt.has_value()) {
                std::cout << "[404] Path not found or escaped root: " << path << std::endl;
                send_404(client_fd, header.stream_id);
                continue;
            }

            fs::path target_file = safe_path_opt.value();
            std::error_code ec;
            uintmax_t file_size = fs::file_size(target_file, ec);
            if (ec) {
                send_404(client_fd, header.stream_id);
                continue;
            }

            // Read file payload
            std::ifstream file(target_file, std::ios::binary);
            if (!file) {
                send_404(client_fd, header.stream_id);
                continue;
            }

            std::vector<uint8_t> file_data(file_size);
            if (file_size > 0) {
                file.read(reinterpret_cast<char*>(file_data.data()), static_cast<std::streamsize>(file_size));
                if (!file) {
                    send_400(client_fd, header.stream_id, "500 File Read Error\n");
                    continue;
                }
            }

            std::string mime = bproto::get_mime_type(target_file.extension().string());

            // Build 200 OK headers
            std::vector<bproto::HeaderField> resp_headers = {
                {":status", "200"},
                {"content-type", mime},
                {"content-length", std::to_string(file_size)},
                {"server", "bserve/1.0"},
                {"date", get_rfc1123_date()},
                {"connection", "keep-alive"}
            };

            // Send HEADERS frame
            bool send_body = (method == "GET");
            if (!send_headers_response(client_fd, header.stream_id, resp_headers, !send_body && (file_size == 0))) {
                break;
            }

            // Send DATA frame(s)
            if (send_body) {
                // We can chunk if payload > 1 MB, or send in one frame (up to 16 MB)
                constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1 MB chunks
                if (file_size == 0) {
                    send_data_response(client_fd, header.stream_id, nullptr, 0, true);
                } else {
                    size_t sent = 0;
                    while (sent < file_size) {
                        size_t chunk_len = std::min(CHUNK_SIZE, static_cast<size_t>(file_size - sent));
                        bool is_last = (sent + chunk_len >= file_size);
                        if (!send_data_response(client_fd, header.stream_id, file_data.data() + sent, chunk_len, is_last)) {
                            break;
                        }
                        sent += chunk_len;
                    }
                }
            }
            std::cout << "[RESP] Stream " << header.stream_id << " -> 200 OK (" << file_size << " bytes)" << std::endl;
        }
    }

    ::close(client_fd);
    std::cout << "[INFO] Closed connection for " << client_ip << ":" << client_port << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <root_directory> <port>\n";
        std::cerr << "Example: " << argv[0] << " ./www 9000\n";
        return 1;
    }

    std::string root_dir_str = argv[1];
    int port = std::atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Error: Invalid port " << argv[2] << std::endl;
        return 1;
    }

    std::error_code ec;
    fs::path canonical_root = fs::canonical(root_dir_str, ec);
    if (ec || !fs::is_directory(canonical_root)) {
        std::cerr << "Error: Root directory does not exist or is not a directory: " << root_dir_str << std::endl;
        return 1;
    }

    // Ignore SIGPIPE to avoid termination on client disconnect
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, sigint_handler);
    std::signal(SIGTERM, sigint_handler);

    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::perror("socket failed");
        return 1;
    }

    int opt = 1;
    if (::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::perror("setsockopt SO_REUSEADDR failed");
        ::close(server_fd);
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(static_cast<uint16_t>(port));

    if (::bind(server_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::perror("bind failed");
        ::close(server_fd);
        return 1;
    }

    if (::listen(server_fd, 128) < 0) {
        std::perror("listen failed");
        ::close(server_fd);
        return 1;
    }

    std::cout << "========================================================\n";
    std::cout << " bserve - High Performance Binary HTTP Server\n";
    std::cout << " Listening on: 0.0.0.0:" << port << "\n";
    std::cout << " Root directory: " << canonical_root.string() << "\n";
    std::cout << " Press Ctrl+C to stop\n";
    std::cout << "========================================================\n";

    while (g_running) {
        pollfd pfd{};
        pfd.fd = server_fd;
        pfd.events = POLLIN;
        int ret = ::poll(&pfd, 1, 300);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            continue; // Poll timeout, loop and check g_running
        }

        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            if (!g_running) break;
            if (errno == EINTR || errno == EAGAIN) continue;
            std::perror("accept failed");
            break;
        }

        char ip_str[INET_ADDRSTRLEN];
        ::inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        uint16_t client_port = ntohs(client_addr.sin_port);

        // Spawn detached thread per client connection
        std::thread([client_fd, ip = std::string(ip_str), client_port, canonical_root]() {
            handle_client(client_fd, ip, client_port, canonical_root);
        }).detach();
    }

    std::cout << "\n[INFO] Server shutting down..." << std::endl;
    ::close(server_fd);
    return 0;
}
