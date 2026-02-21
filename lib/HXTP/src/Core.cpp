/*
 * HXTP Embedded SDK v1.0
 * Core Orchestrator — Implementation
 *
 * Minimal zero-allocation JSON parser + full message pipeline.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Core.h"
#include <cstdio>    /* snprintf */
#include <cstring>   /* memcpy, memset, strcmp, strlen, strncmp */
#include <cstdlib>   /* strtoll */

namespace hxtp {

/* ════════════════════════════════════════════════════════════════════
 *  Minimal Zero-Allocation JSON Parser
 *
 *  Limitations (by design — for embedded):
 *  - Only searches top-level keys (no recursive descent)
 *  - Keys must be double-quoted
 *  - String values must be double-quoted
 *  - Handles basic escapes: \\ \" \n \t \r \/ \b \f
 *  - Does NOT handle \uXXXX (sufficient for HXTP protocol)
 *  - Numeric values: integers only (no float)
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Skip whitespace and return pointer to next non-whitespace char.
 */
static const char* skip_ws(const char* p, const char* end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    return p;
}

/**
 * Find the end of a JSON string (after opening quote).
 * Returns pointer to closing quote, or nullptr.
 */
static const char* find_string_end(const char* p, const char* end) {
    while (p < end) {
        if (*p == '\\') {
            ++p;  /* skip escaped char */
            if (p < end) ++p;
            continue;
        }
        if (*p == '"') return p;
        ++p;
    }
    return nullptr;
}

/**
 * Find the end of a JSON value starting at p.
 * Handles strings, numbers, booleans, null, objects, arrays.
 * Returns pointer to one past the end of the value.
 */
static const char* skip_value(const char* p, const char* end) {
    p = skip_ws(p, end);
    if (p >= end) return end;

    if (*p == '"') {
        /* String */
        const char* close = find_string_end(p + 1, end);
        return close ? close + 1 : end;
    }
    if (*p == '{') {
        /* Object — find matching } */
        int depth = 1;
        ++p;
        while (p < end && depth > 0) {
            if (*p == '"') {
                const char* se = find_string_end(p + 1, end);
                if (!se) return end;
                p = se + 1;
                continue;
            }
            if (*p == '{') ++depth;
            if (*p == '}') --depth;
            ++p;
        }
        return p;
    }
    if (*p == '[') {
        /* Array — find matching ] */
        int depth = 1;
        ++p;
        while (p < end && depth > 0) {
            if (*p == '"') {
                const char* se = find_string_end(p + 1, end);
                if (!se) return end;
                p = se + 1;
                continue;
            }
            if (*p == '[') ++depth;
            if (*p == ']') --depth;
            ++p;
        }
        return p;
    }

    /* Number, boolean, null — advance until separator */
    while (p < end && *p != ',' && *p != '}' && *p != ']'
           && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
        ++p;
    }
    return p;
}

/**
 * Find a key in top-level JSON object and return pointer to its value.
 * p should point to start of JSON (should contain {).
 */
static const char* find_key(const char* json, size_t json_len, const char* key, const char** val_end) {
    const char* p   = json;
    const char* end = json + json_len;

    /* Skip to opening brace */
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return nullptr;
    ++p;

    size_t key_len = strlen(key);

    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return nullptr;

        /* Expect key string */
        if (*p == ',') { ++p; continue; }
        if (*p != '"') return nullptr;

        const char* key_start = p + 1;
        const char* key_end   = find_string_end(key_start, end);
        if (!key_end) return nullptr;

        size_t klen = static_cast<size_t>(key_end - key_start);

        /* Skip to colon */
        p = skip_ws(key_end + 1, end);
        if (p >= end || *p != ':') return nullptr;
        ++p;

        /* Skip whitespace before value */
        p = skip_ws(p, end);
        if (p >= end) return nullptr;

        /* Check if this is our key */
        if (klen == key_len && memcmp(key_start, key, key_len) == 0) {
            /* Found it — p points to start of value */
            const char* ve = skip_value(p, end);
            if (val_end) *val_end = ve;
            return p;
        }

        /* Not our key — skip value */
        p = skip_value(p, end);
    }

    return nullptr;
}

/* ── Public JSON Accessors ──────────────────────────────────────────── */

bool json_get_string(
    const char* json, size_t json_len,
    const char* key,
    char* out, size_t out_cap, size_t* out_len)
{
    if (!json || !key || !out || out_cap == 0) return false;

    const char* val_end = nullptr;
    const char* val = find_key(json, json_len, key, &val_end);
    if (!val || *val != '"') return false;

    /* val points to opening quote */
    const char* str_start = val + 1;
    const char* str_end   = find_string_end(str_start, json + json_len);
    if (!str_end) return false;

    /* Copy with basic unescape */
    size_t wi = 0;
    const char* r = str_start;
    while (r < str_end && wi < out_cap - 1) {
        if (*r == '\\' && r + 1 < str_end) {
            ++r;
            switch (*r) {
                case '"':  out[wi++] = '"';  break;
                case '\\': out[wi++] = '\\'; break;
                case '/':  out[wi++] = '/';  break;
                case 'n':  out[wi++] = '\n'; break;
                case 't':  out[wi++] = '\t'; break;
                case 'r':  out[wi++] = '\r'; break;
                case 'b':  out[wi++] = '\b'; break;
                case 'f':  out[wi++] = '\f'; break;
                default:   out[wi++] = *r;   break;
            }
            ++r;
        } else {
            out[wi++] = *r++;
        }
    }
    out[wi] = '\0';
    if (out_len) *out_len = wi;
    return true;
}

bool json_get_int64(
    const char* json, size_t json_len,
    const char* key,
    int64_t* out)
{
    if (!json || !key || !out) return false;

    const char* val_end = nullptr;
    const char* val = find_key(json, json_len, key, &val_end);
    if (!val) return false;

    /* Value should be a number (no quotes) */
    if (*val == '"') {
        /* String-encoded number — parse inner value */
        ++val;
        /* fall through to strtoll */
    }

    char num_buf[24];
    size_t nlen = static_cast<size_t>(val_end - val);
    if (nlen >= sizeof(num_buf)) nlen = sizeof(num_buf) - 1;

    /* Strip trailing quote if string-encoded */
    while (nlen > 0 && (val[nlen - 1] == '"' || val[nlen - 1] == ' ')) --nlen;

    memcpy(num_buf, val, nlen);
    num_buf[nlen] = '\0';

    char* endp = nullptr;
    *out = strtoll(num_buf, &endp, 10);
    return (endp != num_buf && endp != nullptr);
}

bool json_get_uint16(
    const char* json, size_t json_len,
    const char* key,
    uint16_t* out)
{
    int64_t val = 0;
    if (!json_get_int64(json, json_len, key, &val)) return false;
    if (val < 0 || val > 65535) return false;
    *out = static_cast<uint16_t>(val);
    return true;
}

bool json_get_raw(
    const char* json, size_t json_len,
    const char* key,
    const char** out_ptr, size_t* out_len)
{
    if (!json || !key || !out_ptr || !out_len) return false;

    const char* val_end = nullptr;
    const char* val = find_key(json, json_len, key, &val_end);
    if (!val) return false;

    *out_ptr = val;
    *out_len = static_cast<size_t>(val_end - val);
    return true;
}

/* ════════════════════════════════════════════════════════════════════
 *  HxtpCore Implementation
 * ════════════════════════════════════════════════════════════════════ */

HxtpCore::HxtpCore()
    : initialized_(false)
    , config_(nullptr)
    , storage_(nullptr)
    , platform_(nullptr)
    , secret_loaded_(false)
    , outbound_sequence_(0)
{
    memset(device_id_, 0, sizeof(device_id_));
    memset(tenant_id_, 0, sizeof(tenant_id_));
    memset(client_id_, 0, sizeof(client_id_));
    memset(device_secret_, 0, sizeof(device_secret_));
}

HxtpError HxtpCore::init(
    const HXTPConfig* config,
    const HxtpStorageAdapter* storage,
    const HxtpPlatformCrypto* platform)
{
    if (!config || !platform) return HxtpError::INVALID_PARAMS;
    if (!platform->random_bytes || !platform->get_epoch_ms) return HxtpError::INVALID_PARAMS;

    config_   = config;
    storage_  = storage;
    platform_ = platform;

    /* ── Initialize storage ────────────────────────── */
    if (storage_ && storage_->init) {
        if (!storage_->init()) {
            return HxtpError::STORAGE_INIT_FAILED;
        }
    }

    /* ── Device ID ─────────────────────────────────── */
    if (config_->device_id) {
        size_t dlen = strlen(config_->device_id);
        if (dlen > HXTP_DEVICE_ID_LEN) dlen = HXTP_DEVICE_ID_LEN;
        memcpy(device_id_, config_->device_id, dlen);
        device_id_[dlen] = '\0';
    } else if (storage_ && storage_->read_device_id) {
        if (!storage_->read_device_id(device_id_, sizeof(device_id_))) {
            /* Will be generated during HELLO */
            device_id_[0] = '\0';
        }
    }

    /* ── Tenant ID ─────────────────────────────────── */
    if (config_->tenant_id) {
        size_t tlen = strlen(config_->tenant_id);
        if (tlen > HXTP_UUID_LEN) tlen = HXTP_UUID_LEN;
        memcpy(tenant_id_, config_->tenant_id, tlen);
        tenant_id_[tlen] = '\0';
    }

    /* ── Client ID ─────────────────────────────────── */
    if (config_->client_id) {
        size_t clen = strlen(config_->client_id);
        if (clen > HXTP_UUID_LEN) clen = HXTP_UUID_LEN;
        memcpy(client_id_, config_->client_id, clen);
        client_id_[clen] = '\0';
    } else {
        /* Generate a UUID v4 for this session */
        HxtpError err = crypto::generate_uuid_v4(client_id_, platform_->random_bytes);
        if (err != HxtpError::OK) return err;
    }

    /* ── Device Secret ─────────────────────────────── */
    if (config_->device_secret) {
        /* Decode hex secret */
        size_t decoded_len = 0;
        if (!crypto::hex_decode(
                config_->device_secret, strlen(config_->device_secret),
                device_secret_, &decoded_len) || decoded_len != HXTP_SECRET_LEN) {
            return HxtpError::SECRET_CORRUPT;
        }
        secret_loaded_ = true;
    } else if (storage_ && storage_->read_secret) {
        if (storage_->read_secret(device_secret_, HXTP_SECRET_LEN)) {
            secret_loaded_ = true;
        }
        /* Not fatal — secret may arrive during provisioning */
    }

    /* ── Restore sequence counter ──────────────────── */
    if (storage_ && storage_->read_sequence) {
        int64_t saved = 0;
        if (storage_->read_sequence("seq_out", &saved)) {
            outbound_sequence_ = saved;
        }
    }

    /* ── Initialize validation context ─────────────── */
    val_ctx_.init();
    val_ctx_.get_epoch_ms = platform_->get_epoch_ms;
    memcpy(val_ctx_.device_id, device_id_, HXTP_DEVICE_ID_LEN + 1);
    memcpy(val_ctx_.tenant_id, tenant_id_, HXTP_UUID_LEN + 1);

    if (secret_loaded_) {
        memcpy(val_ctx_.device_secret, device_secret_, HXTP_SECRET_LEN);
        val_ctx_.secret_loaded = true;
    }

    initialized_ = true;
    return HxtpError::OK;
}

/* ════════════════════════════════════════════════════════════════════
 *  JSON Header Parsing
 * ════════════════════════════════════════════════════════════════════ */

HxtpError HxtpCore::parse_json_header(HxtpInboundFrame* frame) {
    const char* json = frame->json_ptr;
    size_t jlen      = frame->json_len;

    if (!json || jlen == 0) return HxtpError::FRAME_JSON_INVALID;

    char buf[128];
    size_t blen = 0;

    /* version */
    if (json_get_string(json, jlen, "version", buf, sizeof(buf), &blen)) {
        frame->header.version.set(buf, blen);
    } else if (json_get_string(json, jlen, "protocol_version", buf, sizeof(buf), &blen)) {
        frame->header.version.set(buf, blen);
    }

    /* message_type */
    if (json_get_string(json, jlen, "message_type", buf, sizeof(buf), &blen)) {
        frame->header.message_type.set(buf, blen);
    }

    /* device_id */
    if (json_get_string(json, jlen, "device_id", buf, sizeof(buf), &blen)) {
        frame->header.device_id.set(buf, blen);
    }

    /* tenant_id */
    if (json_get_string(json, jlen, "tenant_id", buf, sizeof(buf), &blen)) {
        frame->header.tenant_id.set(buf, blen);
    }

    /* client_id */
    if (json_get_string(json, jlen, "client_id", buf, sizeof(buf), &blen)) {
        frame->header.client_id.set(buf, blen);
    }

    /* message_id */
    if (json_get_string(json, jlen, "message_id", buf, sizeof(buf), &blen)) {
        frame->header.message_id.set(buf, blen);
    }

    /* request_id */
    if (json_get_string(json, jlen, "request_id", buf, sizeof(buf), &blen)) {
        frame->header.request_id.set(buf, blen);
    }

    /* nonce */
    if (json_get_string(json, jlen, "nonce", buf, sizeof(buf), &blen)) {
        frame->header.nonce.set(buf, blen);
    }

    /* timestamp (numeric) */
    int64_t ts = 0;
    if (json_get_int64(json, jlen, "timestamp", &ts)) {
        frame->header.timestamp = ts;
    }

    /* sequence_number (numeric) */
    int64_t seq = -1;
    if (json_get_int64(json, jlen, "sequence_number", &seq)) {
        frame->header.sequence_number = seq;
    } else if (json_get_int64(json, jlen, "sequence", &seq)) {
        frame->header.sequence_number = seq;
    } else {
        frame->header.sequence_number = -1;
    }

    /* payload_hash */
    if (json_get_string(json, jlen, "payload_hash", buf, sizeof(buf), &blen)) {
        frame->header.payload_hash.set(buf, blen);
    }

    /* signature */
    if (json_get_string(json, jlen, "signature", buf, sizeof(buf), &blen)) {
        frame->header.signature.set(buf, blen);
    }

    /* Locate raw params object */
    const char* params_ptr = nullptr;
    size_t params_len = 0;
    if (json_get_raw(json, jlen, "params", &params_ptr, &params_len)) {
        frame->params_ptr = params_ptr;
        frame->params_len = static_cast<uint32_t>(params_len);
    } else {
        frame->params_ptr = nullptr;
        frame->params_len = 0;
    }

    return HxtpError::OK;
}

HxtpError HxtpCore::parse_command_payload(HxtpInboundFrame* frame) {
    const char* json = frame->json_ptr;
    size_t jlen      = frame->json_len;

    char buf[64];
    size_t blen = 0;

    /* action */
    if (json_get_string(json, jlen, "action", buf, sizeof(buf), &blen)) {
        frame->command.action.set(buf, blen);
    }

    /* capability_id */
    uint16_t cid = 0;
    if (json_get_uint16(json, jlen, "capability_id", &cid)) {
        frame->command.capability_id = cid;
    }

    return HxtpError::OK;
}

/* ════════════════════════════════════════════════════════════════════
 *  Inbound Message Processing
 * ════════════════════════════════════════════════════════════════════ */

HxtpError HxtpCore::process_inbound(
    const char* topic,
    const uint8_t* raw, size_t raw_len,
    uint8_t* ack_buf, size_t ack_cap, size_t* ack_len)
{
    (void)topic; /* topic used for routing context — not needed for validation */

    if (!initialized_) return HxtpError::NOT_INITIALIZED;
    if (ack_len) *ack_len = 0;

    /* ── Step A: Frame Decode (binary header) ────────── */
    HxtpInboundFrame frame;
    memset(&frame, 0, sizeof(frame));

    HxtpError err = frame_decode(raw, raw_len, &frame);
    if (err != HxtpError::OK) return err;

    /* ── Step B: Parse JSON header ───────────────────── */
    err = parse_json_header(&frame);
    if (err != HxtpError::OK) return err;

    /* ── Step C: Run 7-step validation pipeline ──────── */
    HxtpValidationResult vr = validate_message(&frame, &val_ctx_);
    if (!vr.passed) {
        /* Build error ACK if we have a request_id */
        if (!frame.header.request_id.empty() && ack_buf && ack_cap > 0 && ack_len) {
            build_ack(
                frame.header.request_id.c_str(),
                false,
                vr.reason ? vr.reason : "VALIDATION_FAILED",
                ack_buf, ack_cap, ack_len
            );
        }

        /* Map validation step to error code */
        switch (vr.failed_step) {
            case HxtpValidationStep::VERSION_CHECK:      return HxtpError::VERSION_MISMATCH;
            case HxtpValidationStep::TIMESTAMP_CHECK:    return HxtpError::TIMESTAMP_EXPIRED;
            case HxtpValidationStep::PAYLOAD_SIZE_CHECK:  return HxtpError::PAYLOAD_TOO_LARGE;
            case HxtpValidationStep::NONCE_CHECK:        return HxtpError::NONCE_REUSED;
            case HxtpValidationStep::PAYLOAD_HASH_CHECK: return HxtpError::HASH_MISMATCH;
            case HxtpValidationStep::SEQUENCE_CHECK:     return HxtpError::SEQUENCE_VIOLATION;
            case HxtpValidationStep::SIGNATURE_CHECK:    return HxtpError::SIGNATURE_INVALID;
            default:                                      return HxtpError::INTERNAL_ERROR;
        }
    }

    /* ── Step D: Type-specific processing ────────────── */
    if (frame.wire_type == HxtpMessageTypeBin::COMMAND) {
        /* Parse command-specific fields */
        err = parse_command_payload(&frame);
        if (err != HxtpError::OK) return err;

        if (frame.command.action.empty()) {
            return HxtpError::UNKNOWN_ACTION;
        }

        /* Execute capability */
        HxtpCapabilityResult result = capabilities_.execute(
            frame.command.action.c_str(),
            frame.params_ptr,
            frame.params_len
        );

        /* Build ACK response */
        if (ack_buf && ack_cap > 0 && ack_len) {
            const char* req_id = frame.header.message_id.empty()
                                 ? frame.header.request_id.c_str()
                                 : frame.header.message_id.c_str();

            build_ack(
                req_id,
                result.success,
                result.success ? nullptr : result.error_msg,
                ack_buf, ack_cap, ack_len
            );
        }

        if (!result.success) {
            return HxtpError::UNKNOWN_ACTION;
        }
    }
    else if (frame.wire_type == HxtpMessageTypeBin::HEARTBEAT) {
        /* Heartbeat received — nothing to do (transport layer handles timeout) */
    }

    return HxtpError::OK;
}

/* ════════════════════════════════════════════════════════════════════
 *  Sequence Counter
 * ════════════════════════════════════════════════════════════════════ */

int64_t HxtpCore::next_sequence() {
    ++outbound_sequence_;

    /* Persist if storage available (non-blocking best-effort) */
    if (storage_ && storage_->write_sequence) {
        storage_->write_sequence("seq_out", outbound_sequence_);
    }

    return outbound_sequence_;
}

/* ════════════════════════════════════════════════════════════════════
 *  Outbound Message Construction
 * ════════════════════════════════════════════════════════════════════ */

HxtpError HxtpCore::build_signed_json(
    const char* message_type,
    const char* body_json, uint32_t body_len,
    char* json_out, size_t json_cap, size_t* json_len)
{
    if (!initialized_) return HxtpError::NOT_INITIALIZED;

    /* Generate message_id, nonce */
    char msg_id[37];
    HxtpError err = crypto::generate_uuid_v4(msg_id, platform_->random_bytes);
    if (err != HxtpError::OK) return err;

    char nonce[HXTP_MAX_NONCE_LEN + 1];
    size_t nonce_len = 0;
    err = crypto::generate_nonce(nonce, &nonce_len, platform_->random_bytes);
    if (err != HxtpError::OK) return err;

    /* Timestamp & sequence */
    int64_t ts  = platform_->get_epoch_ms();
    int64_t seq = next_sequence();

    /* Compute payload hash (SHA-256 of body/params JSON) */
    const char* hash_input = (body_json && body_len > 0) ? body_json : "{}";
    uint32_t hash_input_len = (body_json && body_len > 0) ? body_len : 2;
    char payload_hash[HXTP_SHA256_HEX_LEN + 1];
    err = crypto::sha256_hex(hash_input, hash_input_len, payload_hash);
    if (err != HxtpError::OK) return err;

    /* Build canonical string for signature */
    HxtpMessageHeader hdr;
    hdr.version.set(HXTP_VERSION_STRING);
    hdr.message_type.set(message_type);
    hdr.device_id.set(device_id_);
    hdr.tenant_id.set(tenant_id_);
    hdr.timestamp      = ts;
    hdr.message_id.set(msg_id);
    hdr.nonce.set(nonce, nonce_len);

    char canonical[512];
    size_t canonical_len = 0;
    if (!build_canonical_string(&hdr, canonical, sizeof(canonical), &canonical_len)) {
        return HxtpError::BUFFER_OVERFLOW;
    }

    /* Compute HMAC-SHA256 signature */
    char signature[HXTP_HMAC_HEX_LEN + 1];
    if (!secret_loaded_) return HxtpError::SECRET_NOT_FOUND;

    err = crypto::hmac_sha256_hex(
        device_secret_, HXTP_SECRET_LEN,
        canonical, canonical_len,
        signature
    );
    if (err != HxtpError::OK) return err;

    /* Build JSON envelope.
     * We construct it manually to avoid dynamic allocation. */
    int written = snprintf(json_out, json_cap,
        "{"
        "\"version\":\"%s\","
        "\"message_type\":\"%s\","
        "\"message_id\":\"%s\","
        "\"device_id\":\"%s\","
        "\"tenant_id\":\"%s\","
        "\"client_id\":\"%s\","
        "\"timestamp\":%lld,"
        "\"sequence_number\":%lld,"
        "\"nonce\":\"%s\","
        "\"payload_hash\":\"%s\","
        "\"signature\":\"%s\"",
        HXTP_VERSION_STRING,
        message_type,
        msg_id,
        device_id_,
        tenant_id_,
        client_id_,
        static_cast<long long>(ts),
        static_cast<long long>(seq),
        nonce,
        payload_hash,
        signature
    );

    if (written < 0 || static_cast<size_t>(written) >= json_cap) {
        return HxtpError::BUFFER_OVERFLOW;
    }

    /* Append body if present */
    size_t pos = static_cast<size_t>(written);

    if (body_json && body_len > 0) {
        /* Determine key based on message type */
        const char* body_key = "params";
        if (strcmp(message_type, HxtpMessageTypeStr::STATE) == 0) {
            body_key = "state";
        } else if (strcmp(message_type, HxtpMessageTypeStr::TELEMETRY) == 0) {
            body_key = "data";
        } else if (strcmp(message_type, HxtpMessageTypeStr::ACK) == 0) {
            body_key = "result";
        }

        int extra = snprintf(json_out + pos, json_cap - pos,
                             ",\"%s\":%.*s",
                             body_key,
                             static_cast<int>(body_len), body_json);
        if (extra < 0 || pos + static_cast<size_t>(extra) >= json_cap) {
            return HxtpError::BUFFER_OVERFLOW;
        }
        pos += static_cast<size_t>(extra);
    }

    /* Close object */
    if (pos + 2 > json_cap) return HxtpError::BUFFER_OVERFLOW;
    json_out[pos++] = '}';
    json_out[pos]   = '\0';

    *json_len = pos;
    return HxtpError::OK;
}

HxtpError HxtpCore::build_outbound(
    HxtpOutboundContext* ctx,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (!ctx || !out || !out_len) return HxtpError::INVALID_PARAMS;
    if (!initialized_) return HxtpError::NOT_INITIALIZED;

    /* Build signed JSON */
    char json_buf[HXTP_MAX_PAYLOAD_BYTES];
    size_t json_len = 0;

    HxtpError err = build_signed_json(
        ctx->message_type,
        ctx->payload_json, ctx->payload_json_len,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != HxtpError::OK) return err;

    /* Encode binary frame */
    HxtpMessageTypeBin wire_type = frame_str_to_type(ctx->message_type);
    return frame_encode(wire_type, json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

HxtpError HxtpCore::build_heartbeat(
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char json_buf[512];
    size_t json_len = 0;

    HxtpError err = build_signed_json(
        HxtpMessageTypeStr::HEARTBEAT,
        nullptr, 0,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != HxtpError::OK) return err;

    return frame_encode(HxtpMessageTypeBin::HEARTBEAT,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

HxtpError HxtpCore::build_hello(
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    /* HELLO payload includes firmware version and device type */
    char body[256];
    int blen = snprintf(body, sizeof(body),
        "{\"firmware_version\":\"%s\",\"device_type\":\"%s\"}",
        config_->firmware_version ? config_->firmware_version : "0.0.1",
        config_->device_type ? config_->device_type : "esp32"
    );
    if (blen < 0) return HxtpError::BUFFER_OVERFLOW;

    char json_buf[1024];
    size_t json_len = 0;

    HxtpError err = build_signed_json(
        HxtpMessageTypeStr::HELLO,
        body, static_cast<uint32_t>(blen),
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != HxtpError::OK) return err;

    return frame_encode(HxtpMessageTypeBin::HELLO,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

HxtpError HxtpCore::build_state(
    const char* state_json, uint32_t state_len,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char json_buf[HXTP_MAX_PAYLOAD_BYTES];
    size_t json_len = 0;

    HxtpError err = build_signed_json(
        HxtpMessageTypeStr::STATE,
        state_json, state_len,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != HxtpError::OK) return err;

    return frame_encode(HxtpMessageTypeBin::STATE,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

HxtpError HxtpCore::build_telemetry(
    const char* telemetry_json, uint32_t telemetry_len,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char json_buf[HXTP_MAX_PAYLOAD_BYTES];
    size_t json_len = 0;

    HxtpError err = build_signed_json(
        HxtpMessageTypeStr::TELEMETRY,
        telemetry_json, telemetry_len,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != HxtpError::OK) return err;

    return frame_encode(HxtpMessageTypeBin::TELEMETRY,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

HxtpError HxtpCore::build_ack(
    const char* request_id,
    bool success,
    const char* error_msg,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char body[256];
    int blen;
    if (success) {
        blen = snprintf(body, sizeof(body),
            "{\"request_id\":\"%s\",\"status\":\"%s\"}",
            request_id ? request_id : "",
            HxtpAckStatus::EXECUTED
        );
    } else {
        blen = snprintf(body, sizeof(body),
            "{\"request_id\":\"%s\",\"status\":\"%s\",\"error\":\"%s\"}",
            request_id ? request_id : "",
            HxtpAckStatus::FAILED,
            error_msg ? error_msg : "UNKNOWN_ERROR"
        );
    }
    if (blen < 0) return HxtpError::BUFFER_OVERFLOW;

    char json_buf[1024];
    size_t json_len = 0;

    HxtpError err = build_signed_json(
        HxtpMessageTypeStr::ACK,
        body, static_cast<uint32_t>(blen),
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != HxtpError::OK) return err;

    return frame_encode(HxtpMessageTypeBin::ACK,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

/* ════════════════════════════════════════════════════════════════════
 *  MQTT Topic Builder
 * ════════════════════════════════════════════════════════════════════ */

bool HxtpCore::build_topic(
    const char* channel,
    char* out, size_t out_cap)
{
    if (!channel || !out || out_cap == 0) return false;

    /* Format: hxtp/{tenantId}/device/{deviceId}/{channel} */
    int written = snprintf(out, out_cap,
        "hxtp/%s/device/%s/%s",
        tenant_id_, device_id_, channel
    );

    return (written > 0 && static_cast<size_t>(written) < out_cap);
}

} /* namespace hxtp */
