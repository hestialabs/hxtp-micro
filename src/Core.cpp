/*
 * HXTP Embedded SDK v1.0.3
 * Core Orchestrator — Implementation
 *
 * Minimal zero-allocation JSON parser + full message pipeline.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Core.h"
#include "Crypto.h"
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

bool json_get_bool(
    const char* json, size_t json_len,
    const char* key,
    bool* out)
{
    if (!json || !key || !out) return false;

    const char* val_end = nullptr;
    const char* val = find_key(json, json_len, key, &val_end);
    if (!val) return false;

    size_t nlen = static_cast<size_t>(val_end - val);
    if (nlen >= 4 && memcmp(val, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (nlen >= 5 && memcmp(val, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
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
 *  Core Implementation
 * ════════════════════════════════════════════════════════════════════ */

Core::Core()
    : initialized_(false)
    , config_(nullptr)
    , storage_(nullptr)
    , platform_(nullptr)
    , session_()
    , descriptor_()
    , outbound_sequence_(0)
    , val_ctx_({})
{
    memset(client_id_, 0, sizeof(client_id_));
    memset(ed25519_pub_, 0, sizeof(ed25519_pub_));
    memset(ed25519_priv_, 0, sizeof(ed25519_priv_));
    memset(ed25519_pub_hex_, 0, sizeof(ed25519_pub_hex_));
    identity_generated_ = false;
}

Error Core::init(
    const Config* config,
    const StorageAdapter* storage,
    const PlatformCrypto* platform)
{
    if (!config || !platform) return Error::INVALID_PARAMS;
    if (!platform->random_bytes || !platform->get_epoch_ms) return Error::INVALID_PARAMS;

    config_   = config;
    storage_  = storage;
    platform_ = platform;

    /* ── Initialize storage ────────────────────────── */
    if (storage_ && storage_->init) {
        if (!storage_->init()) {
            return Error::STORAGE_INIT_FAILED;
        }
    }

    /* ── Identity ──────────────────────────────────── */
    if (!ensure_identity()) {
        return Error::CRYPTO_INIT_FAILED;
    }

    /* ── Runtime Descriptor Generation ─────────────── */
    if (platform_->get_descriptor) {
        platform_->get_descriptor(&descriptor_);
    }

    /* Override with build-system injection if available */
#ifdef HXTP_BOARD_NAME
    descriptor_.board_name = HXTP_BOARD_NAME;
#endif
#ifdef HXTP_PLATFORM_NAME
    descriptor_.platform_name = HXTP_PLATFORM_NAME;
#endif

    descriptor_.sdk_version = HXTP_SDK_VERSION_TAG;
    descriptor_.capabilities_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /* Generate descriptor hash for attestation */
    calculate_descriptor_hash();

    /* ── Identity (Ed25519) ────────────────────────── */
    if (!ensure_identity()) return Error::KEYGEN_FAILED;

    /* ── Cloud Root Key (compile-time trust anchor) ── */
    {
        const char* root_hex = HXTP_CLOUD_ROOT_KEY;
        size_t klen = 0;
        if (crypto::hex_decode(root_hex, strlen(root_hex), val_ctx_.cloud_root_pub_key, &klen)) {
            if (klen == Ed25519PubKeyLen) {
                val_ctx_.cloud_root_loaded = true;
            }
        }
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
    
    /* Device identity for signing/telemetry */
    memcpy(val_ctx_.device_priv_key, ed25519_priv_, Ed25519PrivKeyLen);
    memcpy(val_ctx_.device_pub_key, ed25519_pub_, Ed25519PubKeyLen);
    val_ctx_.identity_loaded = true;

    initialized_ = true;
    return Error::OK;
}

/* ════════════════════════════════════════════════════════════════════
 *  Runtime Descriptor Hashing
 * ════════════════════════════════════════════════════════════════════ */

void Core::calculate_descriptor_hash() {
    char combined[1024] = {0};
    snprintf(combined, sizeof(combined), "%s|%s|%s|%s|%s|%s",
        descriptor_.platform_name ? descriptor_.platform_name : "",
        descriptor_.board_name ? descriptor_.board_name : "",
        descriptor_.mcu_family ? descriptor_.mcu_family : "",
        descriptor_.sdk_version ? descriptor_.sdk_version : "",
        descriptor_.firmware_hash ? descriptor_.firmware_hash : "",
        descriptor_.capabilities_hash ? descriptor_.capabilities_hash : ""
    );
    
    crypto::sha256_hex(combined, strlen(combined), descriptor_.descriptor_hash.buf);
    descriptor_.descriptor_hash.len = Sha256HexLen;
}

/* ════════════════════════════════════════════════════════════════════
 *  JSON Header Parsing
 * ════════════════════════════════════════════════════════════════════ */

Error Core::parse_json_header(InboundFrame* frame) {
    const char* json = frame->json_ptr;
    size_t jlen      = frame->json_len;

    if (!json || jlen == 0) return Error::FRAME_JSON_INVALID;

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
    
    /* capability */
    if (json_get_string(json, jlen, "capability", buf, sizeof(buf), &blen)) {
        frame->header.capability.set(buf, blen);
    }
    
    /* action */
    if (json_get_string(json, jlen, "action", buf, sizeof(buf), &blen)) {
        frame->header.action.set(buf, blen);
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

    return Error::OK;
}

Error Core::parse_command_payload(InboundFrame* frame) {
    const char* json = frame->json_ptr;
    size_t jlen      = frame->json_len;

    char buf[64];
    size_t blen = 0;

    /* action */
    if (json_get_string(json, jlen, "action", buf, sizeof(buf), &blen)) {
        frame->command.action.set(buf, blen);
    } else {
        return Error::COMMAND_INVALID;
    }

    /* capability_id */
    uint16_t cid = 0;
    if (json_get_uint16(json, jlen, "capability_id", &cid)) {
        frame->command.capability_id = cid;
    }

    return Error::OK;
}

/* ════════════════════════════════════════════════════════════════════
 *  Inbound Message Processing
 * ════════════════════════════════════════════════════════════════════ */

Error Core::process_inbound(
    const char* topic,
    const uint8_t* raw, size_t raw_len,
    uint8_t* ack_buf, size_t ack_cap, size_t* ack_len)
{
    (void)topic; /* topic used for routing context — not needed for validation */

    if (!initialized_) return Error::NOT_INITIALIZED;
    if (ack_len) *ack_len = 0;

    /* ── Step A: Frame Decode (binary header) ────────── */
    InboundFrame frame{};

    Error err = frame_decode(raw, raw_len, &frame);
    if (err != Error::OK) return err;

    /* ── Step B: Parse JSON header ───────────────────── */
    err = parse_json_header(&frame);
    if (err != Error::OK) return err;

    /* ── Step C: Run 7-step validation pipeline ──────── */
    ValidationResult vr = validate_message(&frame, &val_ctx_);
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
            case ValidationStep::VersionCheck:      return Error::VERSION_MISMATCH;
            case ValidationStep::TimestampCheck:    return Error::TIMESTAMP_EXPIRED;
            case ValidationStep::PayloadSizeCheck:  return Error::PAYLOAD_TOO_LARGE;
            case ValidationStep::NonceCheck:        return Error::NONCE_REUSED;
            case ValidationStep::PayloadHashCheck: return Error::HASH_MISMATCH;
            case ValidationStep::SequenceCheck:     return Error::SEQUENCE_VIOLATION;
            case ValidationStep::SignatureCheck:    return Error::SIGNATURE_INVALID;
            default:                                 return Error::INTERNAL_ERROR;
        }
    }

    /* ── Step D: Type-specific processing ────────────── */
    if (frame.wire_type == MessageType::COMMAND) {
        /* Parse command-specific fields */
        err = parse_command_payload(&frame);
        if (err != Error::OK) return err;

        /* Execute capability (Execution Safety Check) */
        CapabilityResult result = capabilities_.execute(
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
            return Error::UNKNOWN_ACTION;
        }
    }
    else if (frame.wire_type == MessageType::HEARTBEAT) {
        /* Heartbeat received — nothing to do (transport layer handles timeout) */
    }

    return Error::OK;
}

/* ════════════════════════════════════════════════════════════════════
 *  Sequence Counter
 * ════════════════════════════════════════════════════════════════════ */

int64_t Core::next_sequence() {
    ++outbound_sequence_;

    /* Persist if storage available (non-blocking best-effort) */
    if (storage_ && storage_->write_sequence) {
        storage_->write_sequence("seq_out", outbound_sequence_);
    }

    return outbound_sequence_;
}

void Core::set_identity(const char* device_id, const char* priv_hex, const char* pub_hex) {
    if (device_id) {
        session_.device_id.set(device_id);
        memcpy(val_ctx_.device_id, session_.device_id.c_str(), DeviceIdLen + 1);
    }
    if (priv_hex) {
        size_t dlen = 0;
        if (crypto::hex_decode(priv_hex, strlen(priv_hex), ed25519_priv_, &dlen) && dlen == Ed25519PrivKeyLen) {
            memcpy(val_ctx_.device_priv_key, ed25519_priv_, Ed25519PrivKeyLen);
        }
    }
    if (pub_hex) {
        size_t dlen = 0;
        if (crypto::hex_decode(pub_hex, strlen(pub_hex), ed25519_pub_, &dlen) && dlen == Ed25519PubKeyLen) {
            memcpy(val_ctx_.device_pub_key, ed25519_pub_, Ed25519PubKeyLen);
            crypto::hex_encode(ed25519_pub_, Ed25519PubKeyLen, ed25519_pub_hex_);
            val_ctx_.identity_loaded = true;
            identity_generated_ = true;
        }
    }
}

/* ════════════════════════════════════════════════════════════════════
 *  Outbound Message Construction
 * ════════════════════════════════════════════════════════════════════ */

Error Core::build_signed_json(
    const char* message_type,
    const char* body_json, uint32_t body_len,
    char* json_out, size_t json_cap, size_t* json_len,
    char* msg_id_out)
{
    if (!initialized_) return Error::NOT_INITIALIZED;

    /* Generate message_id, nonce */
    char msg_id[37];
    Error err = crypto::generate_uuid_v4(msg_id, platform_->random_bytes);
    if (err != Error::OK) return err;

    if (msg_id_out) {
        memcpy(msg_id_out, msg_id, 37);
    }

    char nonce[MaxNonceLen + 1];
    size_t nonce_len = 0;
    err = crypto::generate_nonce(nonce, &nonce_len, platform_->random_bytes);
    if (err != Error::OK) return err;

    /* Timestamp & sequence */
    int64_t ts  = platform_->get_epoch_ms();
    int64_t seq = next_sequence();

    /* Compute payload hash (SHA-256 of canonicalized params JSON) */
    char payload_hash[Sha256HexLen + 1];
    const char* hash_input = (body_json && body_len > 0) ? body_json : "{}";
    uint32_t hash_input_len = (body_json && body_len > 0) ? body_len : 2;

    {
        /* NO CANONICALIZATION: Hash raw payload bytes */
        err = crypto::sha256_hex(hash_input, hash_input_len, payload_hash);
        if (err != Error::OK) return err;
    }

    /* Build canonical JSON for signature */
    MessageHeader hdr;
    hdr.version.set(VersionString);
    hdr.device_id.set(session_.device_id.c_str());
    hdr.tenant_id.set(session_.tenant_id.c_str());
    hdr.client_id.set(client_id_);
    hdr.message_id.set(msg_id);
    hdr.request_id.set(msg_id); // Default RID=MID for outbound
    hdr.timestamp      = ts;
    hdr.sequence_number = seq;
    hdr.nonce.set(nonce, nonce_len);
    hdr.message_type.set(message_type);
    hdr.payload_hash.set(payload_hash);

    char canonical[1024];
    size_t canonical_len = 0;
    if (!build_canonical_string(&hdr, body_json, body_len, canonical, sizeof(canonical), &canonical_len)) {
        return Error::BUFFER_OVERFLOW;
    }

    /* Compute Ed25519 signature */
    uint8_t sig_bin[Ed25519SigLen];
    err = crypto::ed25519_sign(
        reinterpret_cast<const uint8_t*>(canonical), canonical_len,
        ed25519_priv_, ed25519_pub_,
        sig_bin
    );
    if (err != Error::OK) return err;

    char signature[Ed25519SigHexLen + 1];
    crypto::hex_encode(sig_bin, Ed25519SigLen, signature);

    /* Build full outbound JSON (HxTP/3.1) */
    int written = snprintf(json_out, json_cap,
        "{"
        "\"version\":\"%s\","
        "\"device_id\":\"%s\","
        "\"tenant_id\":\"%s\","
        "\"client_id\":\"%s\","
        "\"message_id\":\"%s\","
        "\"request_id\":\"%s\","
        "\"sequence_number\":%lld,"
        "\"timestamp\":%lld,"
        "\"nonce\":\"%s\","
        "\"message_type\":\"%s\","
        "\"payload_hash\":\"%s\","
        "\"params\":%.*s,"
        "\"signature\":\"%s\""
        "}",
        VersionString,
        session_.device_id.c_str(),
        session_.tenant_id.c_str(),
        client_id_,
        msg_id,
        msg_id,
        static_cast<long long>(seq),
        static_cast<long long>(ts),
        nonce,
        message_type,
        payload_hash,
        static_cast<int>(hash_input_len), hash_input,
        signature
    );

    if (written < 0 || static_cast<size_t>(written) >= json_cap) return Error::BUFFER_OVERFLOW;
    if (json_len) *json_len = static_cast<size_t>(written);

    return Error::OK;
}

Error Core::build_outbound(
    const OutboundContext* ctx,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (!ctx || !out || !out_len) return Error::INVALID_PARAMS;
    if (!initialized_) return Error::NOT_INITIALIZED;

    /* Build signed JSON */
    char json_buf[MaxPayloadBytes];
    size_t json_len = 0;

    Error err = build_signed_json(
        ctx->message_type,
        ctx->payload_json, ctx->payload_json_len,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != Error::OK) return err;

    /* Encode binary frame */
    MessageType wire_type = frame_str_to_type(ctx->message_type);
    return frame_encode(wire_type, json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

Error Core::build_heartbeat(
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char json_buf[512];
    size_t json_len = 0;

    Error err = build_signed_json(
        MessageTypeStr::HEARTBEAT,
        nullptr, 0,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != Error::OK) return err;

    return frame_encode(MessageType::HEARTBEAT,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

Error Core::build_hello(
    uint8_t* out, size_t out_cap, size_t* out_len,
    char* msg_id_out)
{
    /* HELLO payload includes dynamic descriptor */
    char body[512];
    int blen = snprintf(body, sizeof(body),
        "{\"platform\":\"%s\",\"board\":\"%s\",\"mcu\":\"%s\",\"sdk_version\":\"%s\",\"firmware_hash\":\"%s\",\"capabilities_hash\":\"%s\",\"descriptor_hash\":\"%s\"}",
        descriptor_.platform_name ? descriptor_.platform_name : "",
        descriptor_.board_name ? descriptor_.board_name : "",
        descriptor_.mcu_family ? descriptor_.mcu_family : "",
        descriptor_.sdk_version ? descriptor_.sdk_version : "",
        descriptor_.firmware_hash ? descriptor_.firmware_hash : "",
        descriptor_.capabilities_hash ? descriptor_.capabilities_hash : "",
        descriptor_.descriptor_hash.c_str()
    );
    if (blen < 0) return Error::BUFFER_OVERFLOW;

    char json_buf[1024];
    size_t json_len = 0;

    Error err = build_signed_json(
        MessageTypeStr::HELLO,
        body, static_cast<uint32_t>(blen),
        json_buf, sizeof(json_buf), &json_len,
        msg_id_out
    );
    if (err != Error::OK) return err;

    return frame_encode(MessageType::HELLO,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

Error Core::build_state(
    const char* state_json, uint32_t state_len,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char json_buf[MaxPayloadBytes];
    size_t json_len = 0;

    Error err = build_signed_json(
        MessageTypeStr::STATE,
        state_json, state_len,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != Error::OK) return err;

    return frame_encode(MessageType::STATE,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

Error Core::build_telemetry(
    const char* telemetry_json, uint32_t telemetry_len,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char json_buf[MaxPayloadBytes];
    size_t json_len = 0;

    Error err = build_signed_json(
        MessageTypeStr::TELEMETRY,
        telemetry_json, telemetry_len,
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != Error::OK) return err;

    return frame_encode(MessageType::TELEMETRY,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

Error Core::build_ack(
    const char* request_id,
    bool success,
    const char* error_msg,
    uint8_t* out, size_t out_cap, size_t* out_len)
{
    char body[256];
    int blen;
    if (success) {
        blen = snprintf(body, sizeof(body),
            "{\"ack_status\":\"executed\",\"ref_message_id\":\"%s\"}",
            request_id ? request_id : ""
        );
    } else {
        blen = snprintf(body, sizeof(body),
            "{\"ack_status\":\"failed\",\"error\":\"%s\",\"ref_message_id\":\"%s\"}",
            error_msg ? error_msg : "UNKNOWN_ERROR",
            request_id ? request_id : ""
        );
    }
    if (blen < 0) return Error::BUFFER_OVERFLOW;

    char json_buf[1024];
    size_t json_len = 0;

    Error err = build_signed_json(
        MessageTypeStr::ACK,
        body, static_cast<uint32_t>(blen),
        json_buf, sizeof(json_buf), &json_len
    );
    if (err != Error::OK) return err;

    return frame_encode(MessageType::ACK,
                        json_buf, static_cast<uint32_t>(json_len),
                        out, out_cap, out_len);
}

/* ════════════════════════════════════════════════════════════════════
 *  MQTT Topic Builder
 * ════════════════════════════════════════════════════════════════════ */

bool Core::build_topic(
    const char* channel,
    char* out, size_t out_cap
) {
    if (!channel || !out) return false;
    if (session_.tenant_id.empty() || session_.device_id.empty()) return false;

    int written = snprintf(out, out_cap, "hxtp/%s/device/%s/%s",
                           session_.tenant_id.c_str(),
                           session_.device_id.c_str(),
                           channel);
    return (written > 0 && static_cast<size_t>(written) < out_cap);
}

bool Core::ensure_identity() {
    bool loaded = false;
    if (storage_ && storage_->read_identity) {
        loaded = storage_->read_identity(ed25519_pub_, ed25519_priv_);
    }

    if (!loaded) {
        Error err = crypto::ed25519_keygen(ed25519_pub_, ed25519_priv_, platform_->random_bytes);
        if (err != Error::OK) return false;

        if (storage_ && storage_->write_identity) {
            storage_->write_identity(ed25519_pub_, ed25519_priv_);
        }
        identity_generated_ = true;
    }

    crypto::hex_encode(ed25519_pub_, Ed25519PubKeyLen, ed25519_pub_hex_);
    memcpy(val_ctx_.device_pub_key, ed25519_pub_, Ed25519PubKeyLen);
    memcpy(val_ctx_.device_priv_key, ed25519_priv_, Ed25519PrivKeyLen);
    val_ctx_.identity_loaded = true;
    return true;
}

Error Core::ed25519_sign(const uint8_t* msg, size_t len, uint8_t sig[Ed25519SigLen]) {
    return crypto::ed25519_sign(msg, len, ed25519_priv_, ed25519_pub_, sig);
}

bool Core::generate_claim_token(char* out, size_t out_cap) {
    char nonce[MaxNonceLen + 1];
    size_t nlen;
    if (crypto::generate_nonce(nonce, &nlen, platform_->random_bytes) != Error::OK) return false;

    int64_t ts = platform_->get_epoch_ms();
    int64_t expiry = ts + 300000; // 5 minutes

    /* Canonical: device_id|pub_hex|nonce|timestamp|expiry */
    char canonical[256];
    int clen = snprintf(canonical, sizeof(canonical), "%s|%s|%s|%lld|%lld",
        ed25519_pub_hex_, ed25519_pub_hex_, nonce, (long long)ts, (long long)expiry);

    if (clen < 0 || (size_t)clen >= sizeof(canonical)) return false;

    uint8_t sig[Ed25519SigLen];
    if (ed25519_sign((uint8_t*)canonical, clen, sig) != Error::OK) return false;

    char sig_hex[Ed25519SigLen * 2 + 1];
    crypto::hex_encode(sig, Ed25519SigLen, sig_hex);

    /* Token format: canonical.signature */
    int tlen = snprintf(out, out_cap, "%s.%s", canonical, sig_hex);
    return (tlen > 0 && (size_t)tlen < out_cap);
}

} /* namespace hxtp */
