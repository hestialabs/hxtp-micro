/*
 * HXTP Embedded SDK v1.0
 * Core Orchestrator — Header
 *
 * Ties together frame decode, JSON parse, validation pipeline,
 * capability dispatch, and outbound message construction.
 *
 * Contains a minimal zero-allocation JSON parser for embedded use.
 *
 * Platform-agnostic. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_CORE_H
#define HXTP_CORE_H

#include "hxtp_types.h"
#include "hxtp_errors.h"
#include "hxtp_frame.h"
#include "hxtp_validation.h"
#include "hxtp_capability.h"
#include "hxtp_crypto.h"

namespace hxtp {

/* ── Minimal JSON Value Accessor (no allocation) ────────────────────── */

/**
 * Extract a string field value from raw JSON.
 * Scans for "key":"value" and copies value into out buffer.
 * Handles escaped characters minimally (\\, \", \n, \t).
 *
 * @param json       Raw JSON buffer
 * @param json_len   JSON buffer length
 * @param key        Key to search for (without quotes)
 * @param out        Output buffer for value
 * @param out_cap    Output capacity
 * @param out_len    Receives value length (excluding null)
 * @return           true if found, false otherwise
 */
bool json_get_string(
    const char* json, size_t json_len,
    const char* key,
    char* out, size_t out_cap, size_t* out_len
);

/**
 * Extract a numeric (int64) field value from raw JSON.
 * Scans for "key":number_value
 *
 * @param json       Raw JSON buffer
 * @param json_len   JSON buffer length
 * @param key        Key to search for
 * @param out        Receives numeric value
 * @return           true if found and parsed, false otherwise
 */
bool json_get_int64(
    const char* json, size_t json_len,
    const char* key,
    int64_t* out
);

/**
 * Extract a uint16 field value from raw JSON.
 */
bool json_get_uint16(
    const char* json, size_t json_len,
    const char* key,
    uint16_t* out
);

/**
 * Find the raw substring for a nested JSON object or value.
 * E.g., for "params":{...}, returns pointer to { and length including }.
 *
 * @param json       Raw JSON buffer
 * @param json_len   JSON buffer length
 * @param key        Key to search for
 * @param out_ptr    Receives pointer to start of value
 * @param out_len    Receives length of value
 * @return           true if found
 */
bool json_get_raw(
    const char* json, size_t json_len,
    const char* key,
    const char** out_ptr, size_t* out_len
);

/* ── Core Engine ────────────────────────────────────────────────────── */

class HxtpCore {
public:
    HxtpCore();

    /**
     * Initialize the core engine.
     * Must be called before any message processing.
     *
     * @param config    SDK configuration
     * @param storage   Platform storage adapter
     * @param platform  Platform crypto (RNG, time)
     * @return          HxtpError::OK or error
     */
    HxtpError init(
        const HXTPConfig* config,
        const HxtpStorageAdapter* storage,
        const HxtpPlatformCrypto* platform
    );

    /**
     * Process a raw inbound MQTT message.
     * Runs the full pipeline: frame decode → JSON parse → validation → dispatch.
     *
     * @param topic      MQTT topic string
     * @param raw        Raw message payload (binary frame)
     * @param raw_len    Payload length
     * @param ack_buf    Buffer for ACK response frame (caller-provided)
     * @param ack_cap    Capacity of ack_buf
     * @param ack_len    Receives length of ACK frame (0 if no ACK needed)
     * @return           HxtpError::OK if processed, or specific error
     */
    HxtpError process_inbound(
        const char* topic,
        const uint8_t* raw, size_t raw_len,
        uint8_t* ack_buf, size_t ack_cap, size_t* ack_len
    );

    /**
     * Build and sign an outbound message frame.
     *
     * @param ctx        Outbound context (type, payload, etc.)
     * @param out        Output buffer for binary frame
     * @param out_cap    Buffer capacity
     * @param out_len    Receives total frame length
     * @return           HxtpError::OK or error
     */
    HxtpError build_outbound(
        HxtpOutboundContext* ctx,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a heartbeat frame.
     */
    HxtpError build_heartbeat(
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a HELLO handshake frame.
     */
    HxtpError build_hello(
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a state report frame.
     */
    HxtpError build_state(
        const char* state_json, uint32_t state_len,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a telemetry frame.
     */
    HxtpError build_telemetry(
        const char* telemetry_json, uint32_t telemetry_len,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build an ACK frame for a command.
     */
    HxtpError build_ack(
        const char* request_id,
        bool success,
        const char* error_msg,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build an MQTT topic string.
     *
     * Format: hxtp/{tenantId}/device/{deviceId}/{channel}
     */
    bool build_topic(
        const char* channel,
        char* out, size_t out_cap
    );

    /* ── Accessors ──────────────────────────────────────── */

    CapabilityRegistry& capabilities() { return capabilities_; }
    ValidationContext&   validation_ctx() { return val_ctx_; }
    int64_t             next_sequence();
    bool                is_initialized() const { return initialized_; }
    const char*         device_id() const { return device_id_; }
    const char*         tenant_id() const { return tenant_id_; }

private:
    /* ── Parse JSON header fields into HxtpInboundFrame ── */
    HxtpError parse_json_header(HxtpInboundFrame* frame);
    HxtpError parse_command_payload(HxtpInboundFrame* frame);

    /* ── Build signed JSON envelope ─────────────────────── */
    HxtpError build_signed_json(
        const char* message_type,
        const char* body_json, uint32_t body_len,
        char* json_out, size_t json_cap, size_t* json_len
    );

    bool                    initialized_;
    const HXTPConfig*       config_;
    const HxtpStorageAdapter* storage_;
    const HxtpPlatformCrypto* platform_;

    /* Identity */
    char    device_id_[HXTP_DEVICE_ID_LEN + 1];
    char    tenant_id_[HXTP_UUID_LEN + 1];
    char    client_id_[HXTP_UUID_LEN + 1];

    /* Secret material */
    uint8_t device_secret_[HXTP_SECRET_LEN];
    bool    secret_loaded_;

    /* Sequence */
    int64_t outbound_sequence_;

    /* Sub-systems */
    ValidationContext    val_ctx_;
    CapabilityRegistry   capabilities_;
};

} /* namespace hxtp */

#endif /* HXTP_CORE_H */
