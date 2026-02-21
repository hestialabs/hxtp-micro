/*
 * HXTP Embedded SDK v1.0
 * Binary Frame Encoder/Decoder — Header
 *
 * Handles the HXTP binary wire format:
 *   [0-1] MAGIC "HX" | [2] VERSION | [3] TYPE | [4-7] JSON_LEN BE | [8..] JSON
 *
 * Platform-agnostic. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_FRAME_H
#define HXTP_FRAME_H

#include "hxtp_types.h"
#include "hxtp_errors.h"

namespace hxtp {

/* ── Frame Decoder ──────────────────────────────────────────────────── */

/**
 * Validate and parse a raw MQTT payload into binary header fields.
 *
 * On success, sets frame->wire_type, frame->json_length,
 * frame->json_ptr, frame->json_len.
 *
 * Does NOT parse JSON — only validates the 8-byte binary header.
 *
 * @param raw       Pointer to raw MQTT payload bytes
 * @param raw_len   Length of raw payload
 * @param frame     Output frame struct
 * @return          HxtpError::OK or specific error
 */
HxtpError frame_decode(const uint8_t* raw, size_t raw_len, HxtpInboundFrame* frame);

/**
 * Validate message type byte is a known type.
 */
bool frame_type_valid(uint8_t type_byte);

/**
 * Convert binary message type to string wire value.
 */
const char* frame_type_to_str(HxtpMessageTypeBin type);

/**
 * Convert string wire value to binary message type.
 * Returns 0 if unknown.
 */
HxtpMessageTypeBin frame_str_to_type(const char* type_str);

/* ── Frame Encoder ──────────────────────────────────────────────────── */

/**
 * Encode an HXTP binary frame into a buffer.
 *
 * Writes: MAGIC(2) + VERSION(1) + TYPE(1) + JSON_LEN(4) + JSON_PAYLOAD
 *
 * @param type       Message type to encode
 * @param json       JSON payload (UTF-8)
 * @param json_len   Length of JSON payload
 * @param out        Output buffer (must be >= HXTP_HEADER_SIZE + json_len)
 * @param out_cap    Capacity of output buffer
 * @param out_len    Receives total bytes written
 * @return           HxtpError::OK or BUFFER_OVERFLOW
 */
HxtpError frame_encode(
    HxtpMessageTypeBin type,
    const char* json,
    uint32_t json_len,
    uint8_t* out,
    size_t out_cap,
    size_t* out_len
);

} /* namespace hxtp */

#endif /* HXTP_FRAME_H */
