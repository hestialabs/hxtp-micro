/*
 * HXTP Embedded SDK v1.0.3
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
 * Extract a boolean field value from raw JSON.
 */
bool json_get_bool(
    const char* json, size_t json_len,
    const char* key,
    bool* out
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
        const OutboundContext* ctx,
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
        uint8_t* out, size_t out_cap, size_t* out_len,
        char* msg_id_out = nullptr
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
    bool                is_secret_loaded() const { return secret_loaded_; }
    const char*         device_id() const { return session_.device_id.c_str(); }
    const char*         tenant_id() const { return session_.tenant_id.c_str(); }
    const char*         client_id() const { return client_id_; }
    const char*         ed25519_pub_hex() const { return ed25519_pub_hex_; }
    Error               ed25519_sign(const uint8_t* msg, size_t len, uint8_t sig[Ed25519SigLen]);
    bool                generate_claim_token(char* out, size_t out_cap);
    void                set_identity(const char* device_id, const char* priv_hex, const char* pub_hex);
    const uint8_t*      device_secret() const { return device_secret_; }
    const StorageAdapter* storage() const { return storage_; }
    const Config*       config() const { return config_; }
    const PlatformCrypto* platform() const { return platform_; }

    SessionMetadata&    session() { return session_; }
    RuntimeDescriptor&  descriptor() { return descriptor_; }

private:
    /* ── Parse JSON header fields into InboundFrame ── */
    Error parse_json_header(InboundFrame* frame);
    Error parse_command_payload(InboundFrame* frame);
    void  calculate_descriptor_hash();

    /* ── Build signed JSON envelope ─────────────────────── */
    Error build_signed_json(
        const char* message_type,
        const char* body_json, uint32_t body_len,
        char* json_out, size_t json_cap, size_t* json_len,
        char* msg_id_out = nullptr
    );

    bool                    ensure_identity();
    bool                    initialized_;
    const Config*           config_;
    const StorageAdapter*   storage_;
    const PlatformCrypto*   platform_;

    /* Dynamic State */
    SessionMetadata         session_;
    RuntimeDescriptor       descriptor_;

    /* Temporary/Session Identity */
    char    client_id_[UuidLen + 1];

    /* Root Identity (Ed25519) */
    uint8_t ed25519_pub_[Ed25519PubKeyLen];
    uint8_t ed25519_priv_[Ed25519PrivKeyLen];
    char    ed25519_pub_hex_[Ed25519PubKeyLen * 2 + 1];
    bool    identity_generated_;

    /* Secret material (HMAC runtime secret) */
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
