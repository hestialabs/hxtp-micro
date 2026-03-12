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

#ifndef CORE_H
#define CORE_H

#include "Types.h"
#include "Errors.h"
#include "Frame.h"
#include "Validation.h"
#include "Capability.h"
#include "Crypto.h"

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

class Core {
public:
    Core();

    /**
     * Initialize the core engine.
     * Must be called before any message processing.
     *
     * @param config    SDK configuration
     * @param storage   Platform storage adapter
     * @param platform  Platform crypto (RNG, time)
     * @return          Error::OK or error
     */
    Error init(
        const Config* config,
        const StorageAdapter* storage,
        const PlatformCrypto* platform
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
     * @return           Error::OK if processed, or specific error
     */
    Error process_inbound(
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
     * @return           Error::OK or error
     */
    Error build_outbound(
        OutboundContext* ctx,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a heartbeat frame.
     */
    Error build_heartbeat(
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a HELLO handshake frame.
     */
    Error build_hello(
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a state report frame.
     */
    Error build_state(
        const char* state_json, uint32_t state_len,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build a telemetry frame.
     */
    Error build_telemetry(
        const char* telemetry_json, uint32_t telemetry_len,
        uint8_t* out, size_t out_cap, size_t* out_len
    );

    /**
     * Build an ACK frame for a command.
     */
    Error build_ack(
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
    const uint8_t*      device_secret() const { return device_secret_; }
    const StorageAdapter* storage() const { return storage_; }
    const Config*       config() const { return config_; }
    const PlatformCrypto* platform() const { return platform_; }

private:
    /* ── Parse JSON header fields into InboundFrame ── */
    Error parse_json_header(InboundFrame* frame);
    Error parse_command_payload(InboundFrame* frame);

    /* ── Build signed JSON envelope ─────────────────────── */
    Error build_signed_json(
        const char* message_type,
        const char* body_json, uint32_t body_len,
        char* json_out, size_t json_cap, size_t* json_len
    );

    bool                    initialized_;
    const Config*           config_;
    const StorageAdapter*   storage_;
    const PlatformCrypto*   platform_;

    /* Identity */
    char    device_id_[DeviceIdLen + 1];
    char    tenant_id_[UuidLen + 1];
    char    client_id_[UuidLen + 1];

    /* Secret material */
    uint8_t device_secret_[SecretLen];
    bool    secret_loaded_;

    /* Sequence */
    int64_t outbound_sequence_;

    /* Sub-systems */
    ValidationContext    val_ctx_;
    CapabilityRegistry   capabilities_;
};

} /* namespace hxtp */

#endif /* CORE_H */
