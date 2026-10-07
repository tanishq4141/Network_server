#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <string_view>
#include <optional>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

namespace bproto {


constexpr size_t FRAME_HEADER_SIZE = 9;       // 3B Length + 1B Type + 1B Flags + 4B StreamID
constexpr uint32_t MAX_PAYLOAD_LENGTH = 0x00FFFFFF; // 16,777,215 bytes (24-bit unsigned, ~16 MB)
constexpr uint32_t STREAM_ID_MASK = 0x7FFFFFFF;     // 31-bit Stream ID (MSB reserved)


enum class FrameType : uint8_t {
    HEADERS  = 0x01,  // Carries binary-encoded HTTP headers
    DATA     = 0x02,  // Carries message payload bytes
    SETTINGS = 0x03,  // Connection/stream configuration or PING
    GOAWAY   = 0x04   // Graceful connection shutdown
};


namespace Flags {
    constexpr uint8_t NONE        = 0x00;
    constexpr uint8_t END_STREAM  = 0x01; // Bit 0: Last frame from sender on this stream
    constexpr uint8_t END_HEADERS = 0x02; // Bit 1: Header block is fully complete
    constexpr uint8_t ACK         = 0x04; // Bit 2: Acknowledgment (SETTINGS / PING)
}

// ============================================================================
// GOAWAY Error Codes (32-bit)
// ============================================================================

enum class ErrorCode : uint32_t {
    NO_ERROR         = 0x00000000,
    PROTOCOL_ERROR   = 0x00000001,
    INTERNAL_ERROR   = 0x00000002,
    FLOW_CONTROL     = 0x00000003,
    STREAM_CLOSED    = 0x00000004
};

// ============================================================================
// Static Indexed Header Table (Indices 0–9)
// ============================================================================

inline const std::array<std::string, 10> STATIC_TABLE = {
    ":method",         // 0
    ":path",           // 1
    ":status",         // 2
    "content-type",    // 3
    "content-length",  // 4
    "server",          // 5
    "user-agent",      // 6
    "host",            // 7
    "date",            // 8
    "connection"       // 9
};

// HPACK-style MSB flag mask for static index encoding
constexpr uint8_t INDEX_MSB_FLAG = 0x80;

inline std::optional<uint8_t> find_static_index(std::string_view name) {
    for (size_t i = 0; i < STATIC_TABLE.size(); ++i) {
        if (STATIC_TABLE[i] == name) {
            return static_cast<uint8_t>(i);
        }
    }
    return std::nullopt;
}

// ============================================================================
// Frame Header Representation
// ============================================================================

struct FrameHeader {
    uint32_t length{0};    // 24-bit payload length (0 .. 16,777,215)
    uint8_t  type{0};      // 8-bit frame type
    uint8_t  flags{0};     // 8-bit flags bitmask
    uint32_t stream_id{0}; // 31-bit stream ID (MSB reserved)

    [[nodiscard]] bool has_flag(uint8_t flag) const noexcept {
        return (flags & flag) != 0;
    }

    [[nodiscard]] std::string type_name() const {
        switch (static_cast<FrameType>(type)) {
            case FrameType::HEADERS:  return "HEADERS";
            case FrameType::DATA:     return "DATA";
            case FrameType::SETTINGS: return "SETTINGS";
            case FrameType::GOAWAY:   return "GOAWAY";
            default:                  return "UNKNOWN(0x" + to_hex(type) + ")";
        }
    }

private:
    static std::string to_hex(uint8_t val) {
        std::ostringstream ss;
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(val);
        return ss.str();
    }
};

// ============================================================================
// Header Field Representation
// ============================================================================

struct HeaderField {
    std::string name;
    std::string value;

    HeaderField() = default;
    HeaderField(std::string n, std::string v) : name(std::move(n)), value(std::move(v)) {}
};

// ============================================================================
// Frame Header Serialization & Deserialization
// ============================================================================

inline std::array<uint8_t, FRAME_HEADER_SIZE> serialize_frame_header(const FrameHeader& h) {
    if (h.length > MAX_PAYLOAD_LENGTH) {
        throw std::invalid_argument("Frame payload length exceeds 24-bit maximum (16 MB)");
    }
    std::array<uint8_t, FRAME_HEADER_SIZE> buf{};

    // Length (24-bit Big-Endian)
    buf[0] = static_cast<uint8_t>((h.length >> 16) & 0xFF);
    buf[1] = static_cast<uint8_t>((h.length >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>(h.length & 0xFF);

    // Type (8-bit)
    buf[3] = h.type;

    // Flags (8-bit)
    buf[4] = h.flags;

    // Stream ID (31-bit Big-Endian, MSB reserved = 0)
    uint32_t sid = h.stream_id & STREAM_ID_MASK;
    buf[5] = static_cast<uint8_t>((sid >> 24) & 0x7F);
    buf[6] = static_cast<uint8_t>((sid >> 16) & 0xFF);
    buf[7] = static_cast<uint8_t>((sid >> 8) & 0xFF);
    buf[8] = static_cast<uint8_t>(sid & 0xFF);

    return buf;
}

inline FrameHeader deserialize_frame_header(const uint8_t* data) {
    FrameHeader h;
    // Length (24-bit Big-Endian)
    h.length = (static_cast<uint32_t>(data[0]) << 16) |
               (static_cast<uint32_t>(data[1]) << 8)  |
               static_cast<uint32_t>(data[2]);

    // Type (8-bit)
    h.type = data[3];

    // Flags (8-bit)
    h.flags = data[4];

    // Stream ID (31-bit Big-Endian, top bit ignored on receive)
    h.stream_id = ((static_cast<uint32_t>(data[5]) & 0x7F) << 24) |
                  (static_cast<uint32_t>(data[6]) << 16)         |
                  (static_cast<uint32_t>(data[7]) << 8)          |
                  static_cast<uint32_t>(data[8]);

    return h;
}

// ============================================================================
// Binary Header Block Encoding & Decoding
// ============================================================================

/**
 * Encodes header fields into a binary block.
 *
 * Encoding Rules:
 * 1. Static Indexed Keys (Indices 0–9):
 *    Encoded as: [table_index: 1 byte][val_len: 2 bytes uint16_t BE][val_str]
 *    (Uses raw index 0x00–0x09).
 * 2. Dynamic / Literal Headers:
 *    Encoded as: [name_len: 2 bytes uint16_t BE][name_str][val_len: 2 bytes uint16_t BE][val_str]
 */
inline std::vector<uint8_t> encode_headers(const std::vector<HeaderField>& headers) {
    std::vector<uint8_t> out;
    out.reserve(256);

    for (const auto& h : headers) {
        auto idx_opt = find_static_index(h.name);
        if (idx_opt.has_value()) {
            // Static Indexed Key
            uint8_t idx = idx_opt.value();
            out.push_back(idx);

            // Value length (16-bit BE)
            uint16_t vlen = static_cast<uint16_t>(h.value.size());
            out.push_back(static_cast<uint8_t>((vlen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(vlen & 0xFF));

            // Value string
            out.insert(out.end(), h.value.begin(), h.value.end());
        } else {
            // Dynamic / Literal Key
            uint16_t nlen = static_cast<uint16_t>(h.name.size());
            out.push_back(static_cast<uint8_t>((nlen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(nlen & 0xFF));

            // Name string
            out.insert(out.end(), h.name.begin(), h.name.end());

            // Value length (16-bit BE)
            uint16_t vlen = static_cast<uint16_t>(h.value.size());
            out.push_back(static_cast<uint8_t>((vlen >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(vlen & 0xFF));

            // Value string
            out.insert(out.end(), h.value.begin(), h.value.end());
        }
    }
    return out;
}

/**
 * Decodes a binary header block.
 *
 * Fully supports:
 * - Raw static index (0x00–0x09)
 * - HPACK-flagged static index (0x80–0x89)
 * - Dynamic / Literal headers with 16-bit name_len
 */
inline std::vector<HeaderField> decode_headers(const uint8_t* data, size_t size) {
    std::vector<HeaderField> headers;
    size_t offset = 0;

    while (offset < size) {
        uint8_t first_byte = data[offset];

        // Case 1: HPACK-style index with bit 7 set (0x80 .. 0x89)
        if ((first_byte & INDEX_MSB_FLAG) != 0) {
            uint8_t idx = first_byte & 0x7F;
            if (idx >= STATIC_TABLE.size()) {
                throw std::runtime_error("Invalid static header index: " + std::to_string(idx));
            }
            offset += 1;
            if (offset + 2 > size) {
                throw std::runtime_error("Unexpected EOF reading value length for static index");
            }
            uint16_t vlen = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;
            if (offset + vlen > size) {
                throw std::runtime_error("Unexpected EOF reading value string for static index");
            }
            std::string val(reinterpret_cast<const char*>(data + offset), vlen);
            offset += vlen;
            headers.emplace_back(STATIC_TABLE[idx], std::move(val));
            continue;
        }

        // Case 2: Disambiguate between raw static index (0x00..0x09) vs 16-bit name_len
        // If first_byte is 0x00..0x09:
        // A raw static index entry is [idx: 1B][val_len: 2B][val: val_len B].
        // If it were a literal header, the first 2 bytes would be name_len.
        // For name_len = (first_byte << 8) | data[offset+1]:
        // If first_byte == 0 and data[offset+1] == 0, name_len = 0 which is illegal for header name.
        // Thus if data[offset+1] == 0, it MUST be a raw static index with val_len < 256.
        bool is_raw_static = false;
        if (first_byte < STATIC_TABLE.size() && (offset + 3 <= size)) {
            // Check if parsing as static index leaves a valid remaining sequence
            uint16_t candidate_vlen = (static_cast<uint16_t>(data[offset + 1]) << 8) | data[offset + 2];
            size_t entry_len = 3 + candidate_vlen;
            if (offset + entry_len <= size) {
                // If it ends exactly at size or next byte starts a valid header, treat as static
                if (data[offset + 1] == 0 || (offset + entry_len == size)) {
                    is_raw_static = true;
                }
            }
        }

        if (is_raw_static) {
            uint8_t idx = first_byte;
            offset += 1;
            uint16_t vlen = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;
            std::string val(reinterpret_cast<const char*>(data + offset), vlen);
            offset += vlen;
            headers.emplace_back(STATIC_TABLE[idx], std::move(val));
        } else {
            // Dynamic / Literal header
            if (offset + 2 > size) {
                throw std::runtime_error("Unexpected EOF reading literal name length");
            }
            uint16_t nlen = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;
            if (nlen == 0 || offset + nlen > size) {
                throw std::runtime_error("Invalid or out-of-bounds literal name length: " + std::to_string(nlen));
            }
            std::string name(reinterpret_cast<const char*>(data + offset), nlen);
            offset += nlen;

            if (offset + 2 > size) {
                throw std::runtime_error("Unexpected EOF reading literal value length");
            }
            uint16_t vlen = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;
            if (offset + vlen > size) {
                throw std::runtime_error("Unexpected EOF reading literal value string");
            }
            std::string val(reinterpret_cast<const char*>(data + offset), vlen);
            offset += vlen;
            headers.emplace_back(std::move(name), std::move(val));
        }
    }

    return headers;
}

// ============================================================================
// Helper Utilities: Hex Formatting
// ============================================================================

inline std::string format_hex_dump(const uint8_t* data, size_t size, size_t bytes_per_line = 16) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; i += bytes_per_line) {
        oss << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        size_t line_len = std::min(bytes_per_line, size - i);
        for (size_t j = 0; j < bytes_per_line; ++j) {
            if (j < line_len) {
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i + j]) << " ";
            } else {
                oss << "   ";
            }
            if (j == 7) oss << " ";
        }
        oss << " |";
        for (size_t j = 0; j < line_len; ++j) {
            uint8_t c = data[i + j];
            if (c >= 32 && c <= 126) {
                oss << static_cast<char>(c);
            } else {
                oss << '.';
            }
        }
        oss << "|\n";
    }
    return oss.str();
}

// ============================================================================
// MIME Type Resolver
// ============================================================================

inline std::string get_mime_type(std::string_view extension) {
    std::string ext(extension);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == ".html" || ext == ".htm") return "text/html; charset=utf-8";
    if (ext == ".css")  return "text/css; charset=utf-8";
    if (ext == ".js" || ext == ".mjs")  return "application/javascript; charset=utf-8";
    if (ext == ".json") return "application/json";
    if (ext == ".txt")  return "text/plain; charset=utf-8";
    if (ext == ".png")  return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif")  return "image/gif";
    if (ext == ".svg")  return "image/svg+xml";
    if (ext == ".pdf")  return "application/pdf";
    if (ext == ".bin" || ext == ".dat") return "application/octet-stream";
    return "application/octet-stream";
}

} // namespace bproto
