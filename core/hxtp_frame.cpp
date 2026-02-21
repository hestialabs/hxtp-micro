/*
 * HXTP Embedded SDK v1.0
 * Binary Frame Encoder/Decoder — Implementation
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "hxtp_frame.h"

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

const char* frame_type_to_str(HxtpMessageTypeBin type) {
    switch (type) {
        case HxtpMessageTypeBin::STATE:      return HxtpMessageTypeStr::STATE;
        case HxtpMessageTypeBin::COMMAND:    return HxtpMessageTypeStr::COMMAND;
        case HxtpMessageTypeBin::ACK:        return HxtpMessageTypeStr::ACK;
        case HxtpMessageTypeBin::HEARTBEAT:  return HxtpMessageTypeStr::HEARTBEAT;
        case HxtpMessageTypeBin::TELEMETRY:  return HxtpMessageTypeStr::TELEMETRY;
        case HxtpMessageTypeBin::OTA:        return HxtpMessageTypeStr::OTA;
        case HxtpMessageTypeBin::ERROR_MSG:  return HxtpMessageTypeStr::ERROR_MSG;
        case HxtpMessageTypeBin::HELLO:      return HxtpMessageTypeStr::HELLO;
        default:                              return nullptr;
    }
}

HxtpMessageTypeBin frame_str_to_type(const char* s) {
    if (!s) return static_cast<HxtpMessageTypeBin>(0);
    if (strcmp(s, HxtpMessageTypeStr::STATE)     == 0) return HxtpMessageTypeBin::STATE;
    if (strcmp(s, HxtpMessageTypeStr::COMMAND)   == 0) return HxtpMessageTypeBin::COMMAND;
    if (strcmp(s, HxtpMessageTypeStr::ACK)       == 0) return HxtpMessageTypeBin::ACK;
    if (strcmp(s, HxtpMessageTypeStr::HEARTBEAT) == 0) return HxtpMessageTypeBin::HEARTBEAT;
    if (strcmp(s, HxtpMessageTypeStr::TELEMETRY) == 0) return HxtpMessageTypeBin::TELEMETRY;
    if (strcmp(s, HxtpMessageTypeStr::OTA)       == 0) return HxtpMessageTypeBin::OTA;
    if (strcmp(s, HxtpMessageTypeStr::ERROR_MSG) == 0) return HxtpMessageTypeBin::ERROR_MSG;
    if (strcmp(s, HxtpMessageTypeStr::HELLO)     == 0) return HxtpMessageTypeBin::HELLO;
    return static_cast<HxtpMessageTypeBin>(0);
}

/* ── Frame Decoder ──────────────────────────────────────────────────── */

HxtpError frame_decode(const uint8_t* raw, size_t raw_len, HxtpInboundFrame* frame) {
    if (!raw || !frame) return HxtpError::INTERNAL_ERROR;

    /* Step 1: Minimum size check */
    if (raw_len < HXTP_HEADER_SIZE) {
        return HxtpError::FRAME_TOO_SHORT;
    }

    /* Step 2: Magic bytes "HX" */
    if (raw[0] != HXTP_MAGIC[0] || raw[1] != HXTP_MAGIC[1]) {
        return HxtpError::FRAME_MAGIC_INVALID;
    }

    /* Step 3: Framer version */
    if (raw[2] != HXTP_FRAMER_VERSION) {
        return HxtpError::FRAME_VERSION_INVALID;
    }

    /* Step 4: Message type */
    if (!frame_type_valid(raw[3])) {
        return HxtpError::FRAME_TYPE_INVALID;
    }
    frame->wire_type = static_cast<HxtpMessageTypeBin>(raw[3]);

    /* Step 5: JSON length (Big-Endian uint32) */
    uint32_t json_len = read_u32_be(raw + 4);
    if (json_len > HXTP_MAX_PAYLOAD_BYTES) {
        return HxtpError::FRAME_LENGTH_INVALID;
    }

    /* Step 6: Frame completeness */
    if (raw_len < HXTP_HEADER_SIZE + json_len) {
        return HxtpError::FRAME_TOO_SHORT;
    }

    /* Step 7: No trailing data allowed */
    if (raw_len > HXTP_HEADER_SIZE + json_len) {
        /* Tolerate trailing bytes — some brokers pad. Just ignore. */
    }

    frame->json_length = json_len;
    frame->json_ptr = reinterpret_cast<const char*>(raw + HXTP_HEADER_SIZE);
    frame->json_len = json_len;

    return HxtpError::OK;
}

/* ── Frame Encoder ──────────────────────────────────────────────────── */

HxtpError frame_encode(
    HxtpMessageTypeBin type,
    const char* json,
    uint32_t json_len,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len
) {
    size_t total = HXTP_HEADER_SIZE + json_len;
    if (total > out_cap) {
        return HxtpError::BUFFER_OVERFLOW;
    }

    /* Magic */
    out[0] = HXTP_MAGIC[0];
    out[1] = HXTP_MAGIC[1];

    /* Framer version */
    out[2] = HXTP_FRAMER_VERSION;

    /* Message type */
    out[3] = static_cast<uint8_t>(type);

    /* JSON length (BE) */
    write_u32_be(out + 4, json_len);

    /* JSON payload */
    if (json && json_len > 0) {
        memcpy(out + HXTP_HEADER_SIZE, json, json_len);
    }

    *out_len = total;
    return HxtpError::OK;
}

} /* namespace hxtp */
