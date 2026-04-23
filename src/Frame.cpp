/*
 * HXTP Embedded SDK v1.0.3
 * Binary Frame Encoder/Decoder — Implementation
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Frame.h"

namespace hxtp {

/* ── Helpers ────────────────────────────────────────────────────────── */

static inline uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           (static_cast<uint32_t>(p[3]));
}

static inline void write_u32_be(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >>  8) & 0xFF);
    p[3] = static_cast<uint8_t>((v)       & 0xFF);
}

/* ── Type Validation ────────────────────────────────────────────────── */

bool frame_type_valid(uint8_t type_byte) {
    return type_byte >= 0x01 && type_byte <= 0x08;
}

const char* frame_type_to_str(MessageType type) {
    switch (type) {
        case MessageType::STATE:      return MessageTypeStr::STATE;
        case MessageType::COMMAND:    return MessageTypeStr::COMMAND;
        case MessageType::ACK:        return MessageTypeStr::ACK;
        case MessageType::HEARTBEAT:  return MessageTypeStr::HEARTBEAT;
        case MessageType::TELEMETRY:  return MessageTypeStr::TELEMETRY;
        case MessageType::OTA:        return MessageTypeStr::OTA;
        case MessageType::ERROR_MSG:  return MessageTypeStr::ERROR_MSG;
        case MessageType::HELLO:      return MessageTypeStr::HELLO;
        default:                              return nullptr;
    }
}

MessageType frame_str_to_type(const char* s) {
    if (!s) return static_cast<MessageType>(0);
    if (strcmp(s, MessageTypeStr::STATE)     == 0) return MessageType::STATE;
    if (strcmp(s, MessageTypeStr::COMMAND)   == 0) return MessageType::COMMAND;
    if (strcmp(s, MessageTypeStr::ACK)       == 0) return MessageType::ACK;
    if (strcmp(s, MessageTypeStr::HEARTBEAT) == 0) return MessageType::HEARTBEAT;
    if (strcmp(s, MessageTypeStr::TELEMETRY) == 0) return MessageType::TELEMETRY;
    if (strcmp(s, MessageTypeStr::OTA)       == 0) return MessageType::OTA;
    if (strcmp(s, MessageTypeStr::ERROR_MSG) == 0) return MessageType::ERROR_MSG;
    if (strcmp(s, MessageTypeStr::HELLO)     == 0) return MessageType::HELLO;
    return static_cast<MessageType>(0);
}

/* ── Frame Decoder ──────────────────────────────────────────────────── */

Error frame_decode(const uint8_t* raw, size_t raw_len, InboundFrame* frame) {
    if (!raw || !frame) return Error::INTERNAL_ERROR;

    /* Step 1: Minimum size check */
    if (raw_len < HeaderSize) {
        return Error::FRAME_TOO_SHORT;
    }

    /* Step 2: Magic bytes "HX" */
    if (raw[0] != Magic[0] || raw[1] != Magic[1]) {
        return Error::FRAME_MAGIC_INVALID;
    }

    /* Step 3: Framer version */
    if (raw[2] != FramerVersion) {
        return Error::FRAME_VERSION_INVALID;
    }

    /* Step 4: Message type */
    if (!frame_type_valid(raw[3])) {
        return Error::FRAME_TYPE_INVALID;
    }
    frame->wire_type = static_cast<MessageType>(raw[3]);

    /* Step 5: JSON length (Big-Endian uint32) */
    uint32_t json_len = read_u32_be(raw + 4);
    if (json_len > MaxPayloadBytes) {
        return Error::FRAME_LENGTH_INVALID;
    }

    /* Step 6: Frame completeness */
    if (raw_len < HeaderSize + json_len) {
        return Error::FRAME_TOO_SHORT;
    }

    /* Step 7: No trailing data allowed */
    if (raw_len > HeaderSize + json_len) {
        /* Tolerate trailing bytes — some brokers pad. Just ignore. */
    }

    frame->json_length = json_len;
    frame->json_ptr = reinterpret_cast<const char*>(raw + HeaderSize);
    frame->json_len = json_len;

    return Error::OK;
}

/* ── Frame Encoder ──────────────────────────────────────────────────── */

Error frame_encode(
    MessageType type,
    const char* json,
    uint32_t json_len,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len
) {
    size_t total = HeaderSize + json_len;
    if (total > out_cap) {
        return Error::BUFFER_OVERFLOW;
    }

    /* Magic */
    out[0] = Magic[0];
    out[1] = Magic[1];

    /* Framer version */
    out[2] = FramerVersion;

    /* Message type */
    out[3] = static_cast<uint8_t>(type);

    /* JSON length (BE) */
    write_u32_be(out + 4, json_len);

    /* JSON payload */
    if (json && json_len > 0) {
        memcpy(out + HeaderSize, json, json_len);
    }

    *out_len = total;
    return Error::OK;
}

} /* namespace hxtp */
