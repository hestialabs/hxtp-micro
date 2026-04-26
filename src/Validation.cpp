/*
 * HXTP Embedded SDK v1.0.3
 * 7-Step Validation Pipeline — Implementation
 *
 * FROZEN pipeline order:
 *   1. Version check
 *   2. Timestamp freshness
 *   3. Payload size enforcement
 *   4. Nonce uniqueness
 *   5. Payload hash verification
 *   6. Sequence monotonicity
 *   7. HMAC-SHA256 signature verification
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Validation.h"
#include "Crypto.h"
#include <cstdio>     /* snprintf */
#include <cstring>    /* strcmp, memset */

namespace hxtp {

/* ════════════════════════════════════════════════════════════════════
 *  NonceCache
 * ════════════════════════════════════════════════════════════════════ */

void NonceCache::init() {
    memset(entries, 0, sizeof(entries));
    head  = 0;
    count = 0;
}

bool NonceCache::check_and_insert(const char* nonce, int64_t now_ms) {
    if (!nonce || nonce[0] == '\0') return true;  /* empty nonce = treat as dup (reject) */

    const int64_t ttl_ms = static_cast<int64_t>(NonceTtlSec) * 1000;

    /* ── Pass 1: Check for duplicate & evict expired ──── */
    for (size_t i = 0; i < count; ++i) {
        NonceEntry& e = entries[i];

        /* Evict expired entries */
        if ((now_ms - e.timestamp_ms) > ttl_ms) {
            e.nonce[0]     = '\0';
            e.timestamp_ms = 0;
            continue;
        }

        /* Duplicate check (constant-time NOT needed here — nonce is not secret) */
        if (strcmp(e.nonce, nonce) == 0) {
            return true; /* DUPLICATE */
        }
    }

    /* ── Insert into ring buffer ──────────────────────── */
    NonceEntry& slot = entries[head];
    size_t nlen = strlen(nonce);
    if (nlen > MaxNonceLen) nlen = MaxNonceLen;
    memcpy(slot.nonce, nonce, nlen);
    slot.nonce[nlen]  = '\0';
    slot.timestamp_ms = now_ms;

    head = (head + 1) % NonceCacheSize;
    if (count < NonceCacheSize) ++count;

    return false; /* NOT duplicate */
}

/* ════════════════════════════════════════════════════════════════════
 *  SequenceTracker
 * ════════════════════════════════════════════════════════════════════ */

bool SequenceTracker::check_and_advance(int64_t seq) {
    if (!initialized) {
        last_sequence = seq;
        initialized   = true;
        return true;
    }
    if (seq <= last_sequence) {
        return false; /* VIOLATION: not strictly increasing */
    }
    last_sequence = seq;
    return true;
}

/* ════════════════════════════════════════════════════════════════════
 *  ValidationContext
 * ════════════════════════════════════════════════════════════════════ */

void ValidationContext::init() {
    memset(device_secret, 0, sizeof(device_secret));
    secret_loaded = false;
    memset(prev_secret, 0, sizeof(prev_secret));
    prev_secret_loaded = false;
    nonce_cache.init();
    sequence.init();
    get_epoch_ms = nullptr;
    memset(device_id, 0, sizeof(device_id));
    memset(tenant_id, 0, sizeof(tenant_id));
}

/* ════════════════════════════════════════════════════════════════════
 *  Canonical String Builder
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Builds a strict Canonical JSON string of the signable message fields.
 * Lexicographical order:
 * client_id, device_id, message_id, message_type, nonce, params, payload_hash, request_id, sequence_number, tenant_id, timestamp, version
 */
bool build_canonical_json(
    const MessageHeader* hdr,
    const char* params_json,
    uint32_t params_len,
    char* out,
    size_t out_cap,
    size_t* out_len)
{
    if (!hdr || !out || out_cap == 0) return false;

    // We build the JSON manually to avoid dynamic allocation, but ensure lexicographical order.
    // NOTE: This must match the backend CanonicalJson output exactly.
    int written = snprintf(out, out_cap,
        "{"
        "\"client_id\":\"%s\","
        "\"device_id\":\"%s\","
        "\"message_id\":\"%s\","
        "\"message_type\":\"%s\","
        "\"nonce\":\"%s\","
        "\"params\":%.*s,"
        "\"payload_hash\":\"%s\","
        "\"request_id\":\"%s\","
        "\"sequence_number\":%lld,"
        "\"tenant_id\":\"%s\","
        "\"timestamp\":%lld,"
        "\"version\":\"%s\""
        "}",
        hdr->client_id.c_str(),
        hdr->device_id.c_str(),
        hdr->message_id.c_str(),
        hdr->message_type.c_str(),
        hdr->nonce.c_str(),
        static_cast<int>(params_len > 0 ? params_len : 2), (params_json && params_len > 0) ? params_json : "{}",
        hdr->payload_hash.c_str(),
        hdr->request_id.c_str(),
        static_cast<long long>(hdr->sequence_number),
        hdr->tenant_id.c_str(),
        static_cast<long long>(hdr->timestamp),
        hdr->version.c_str()
    );

    if (written < 0 || static_cast<size_t>(written) >= out_cap) return false;
    if (out_len) *out_len = static_cast<size_t>(written);
    return true;
}

/* ════════════════════════════════════════════════════════════════════
 *  Individual Validation Steps
 * ════════════════════════════════════════════════════════════════════ */

/* ── Step 1: Version Check ──────────────────────────────────────── */

ValidationResult validate_version(const InboundFrame* frame) {
    if (!frame->header.version.equals(VersionString)) {
        return ValidationResult::fail(
            ValidationStep::VersionCheck,
            "VERSION_MISMATCH: unsupported protocol version"
        );
    }
    return ValidationResult::ok();
}

/* ── Step 2: Timestamp Freshness ─────────────────────────────────── */

ValidationResult validate_timestamp(const InboundFrame* frame, int64_t now_ms) {
    const int64_t ts = frame->header.timestamp;

    /*
     * The server validator normalizes to seconds:
     *   const Now = Math.floor(Date.now() / 1000)
     *   const AgeSec = Now - MsgTimestamp
     *
     * We do the same to stay compatible.
     * If the timestamp is in milliseconds (> 1e12), we convert.
     */
    int64_t now_sec = now_ms / 1000;
    int64_t ts_sec  = ts;
    if (ts > 1000000000000LL) {
        /* Timestamp appears to be in milliseconds — convert */
        ts_sec = ts / 1000;
    }

    int64_t age_sec = now_sec - ts_sec;

    /* Strict 30s window */
    if (age_sec > 30) {
        return ValidationResult::fail(
            ValidationStep::TimestampCheck,
            "TIMESTAMP_EXPIRED: message too old (>30s)"
        );
    }
    if (age_sec < -30) {
        return ValidationResult::fail(
            ValidationStep::TimestampCheck,
            "TIMESTAMP_FUTURE: clock skew exceeds 30s"
        );
    }

    return ValidationResult::ok();
}

/* ── Step 3: Payload Size ────────────────────────────────────────── */

ValidationResult validate_payload_size(const InboundFrame* frame) {
    if (frame->json_len > MaxPayloadBytes) {
        return ValidationResult::fail(
            ValidationStep::PayloadSizeCheck,
            "PAYLOAD_TOO_LARGE: exceeds 16KB limit"
        );
    }
    return ValidationResult::ok();
}

/* ── Step 4: Nonce Uniqueness ────────────────────────────────────── */

ValidationResult validate_nonce(
    const InboundFrame* frame,
    NonceCache* cache,
    int64_t now_ms)
{
    if (frame->header.nonce.empty()) {
        return ValidationResult::fail(
            ValidationStep::NonceCheck,
            "NONCE_MISSING: nonce field is empty"
        );
    }

    bool is_dup = cache->check_and_insert(frame->header.nonce.c_str(), now_ms);
    if (is_dup) {
        return ValidationResult::fail(
            ValidationStep::NonceCheck,
            "NONCE_REUSED: replay attack detected"
        );
    }

    return ValidationResult::ok();
}

/* ── Step 5: Payload Hash ────────────────────────────────────────── */

ValidationResult validate_payload_hash(const InboundFrame* frame) {
    /* If no payload_hash provided, skip (matches server behavior —
     * server checks "if (Msg.payload_hash)") */
    if (frame->header.payload_hash.empty()) {
        return ValidationResult::ok();
    }

    /* If no params payload, the hash should be of "{}" (empty JSON object).
     * We compute SHA-256 of the raw params JSON. */
    const char* params = frame->params_ptr;
    uint32_t    plen   = frame->params_len;

    /* Fallback: if params not parsed yet, use empty object */
    const char empty_obj[] = "{}";
    if (!params || plen == 0) {
        params = empty_obj;
        plen   = 2;
    }

    char computed_hex[Sha256HexLen + 1];
    Error err = crypto::sha256_hex(params, plen, computed_hex);
    if (err != Error::OK) {
        return ValidationResult::fail(
            ValidationStep::PayloadHashCheck,
            "HASH_COMPUTE_FAILED: could not compute SHA-256"
        );
    }

    /* Compare hashes — NOT constant-time (payload hash is not a secret) */
    if (strcmp(computed_hex, frame->header.payload_hash.c_str()) != 0) {
        return ValidationResult::fail(
            ValidationStep::PayloadHashCheck,
            "HASH_MISMATCH: payload hash does not match"
        );
    }

    return ValidationResult::ok();
}

/* ── Step 6: Sequence Monotonicity ───────────────────────────────── */

ValidationResult validate_sequence(
    const InboundFrame* frame,
    SequenceTracker* tracker)
{
    /* If no sequence_number provided, skip (optional field) */
    if (frame->header.sequence_number < 0) {
        return ValidationResult::ok();
    }

    bool valid = tracker->check_and_advance(frame->header.sequence_number);
    if (!valid) {
        return ValidationResult::fail(
            ValidationStep::SequenceCheck,
            "SEQUENCE_VIOLATION: out-of-order or duplicate sequence"
        );
    }

    return ValidationResult::ok();
}

/* ── Step 7: HMAC-SHA256 Signature ───────────────────────────────── */

ValidationResult validate_signature(
    const InboundFrame* frame,
    const uint8_t* secret, size_t secret_len,
    const uint8_t* prev_secret, bool has_prev)
{
    if (frame->header.signature.empty()) {
        return ValidationResult::fail(
            ValidationStep::SignatureCheck,
            "SIGNATURE_MISSING: signature field is empty"
        );
    }

    /* Build canonical JSON */
    char canonical[1024];
    size_t canonical_len = 0;
    if (!build_canonical_json(&frame->header, frame->params_ptr, frame->params_len, canonical, sizeof(canonical), &canonical_len)) {
        return ValidationResult::fail(
            ValidationStep::SignatureCheck,
            "CANONICAL_BUILD_FAILED: could not build canonical JSON"
        );
    }

    /* Compute HMAC-SHA256 with primary secret */
    char computed_hex[HmacHexLen + 1];
    Error err = crypto::hmac_sha256_hex(
        secret, secret_len,
        canonical, canonical_len,
        computed_hex
    );
    if (err != Error::OK) {
        return ValidationResult::fail(
            ValidationStep::SignatureCheck,
            "HMAC_COMPUTE_FAILED: could not compute HMAC"
        );
    }

    /* Constant-time compare */
    if (crypto::constant_time_hex_equal(computed_hex, frame->header.signature.c_str(), HmacHexLen)) {
        return ValidationResult::ok();
    }

    /* ── Fallback: try previous secret (key rotation window) ─────── */
    if (has_prev && prev_secret) {
        err = crypto::hmac_sha256_hex(
            prev_secret, secret_len,
            canonical, canonical_len,
            computed_hex
        );
        if (err != Error::OK) {
            return ValidationResult::fail(
                ValidationStep::SignatureCheck,
                "HMAC_COMPUTE_FAILED: previous secret HMAC failed"
            );
        }

        if (crypto::constant_time_hex_equal(
                computed_hex,
                frame->header.signature.c_str(),
                HmacHexLen))
        {
            /* Verified with previous secret — rotation in progress */
            return ValidationResult::ok();
        }
    }

    /* Both secrets failed */
    return ValidationResult::fail(
        ValidationStep::SignatureCheck,
        "SIGNATURE_INVALID: HMAC verification failed"
    );
}

/* ════════════════════════════════════════════════════════════════════
 *  Full Validation Pipeline
 * ════════════════════════════════════════════════════════════════════ */

ValidationResult validate_message(
    const InboundFrame* frame,
    ValidationContext* ctx)
{
    if (!frame || !ctx) {
        return ValidationResult::fail(
            ValidationStep::VersionCheck,
            "NULL_INPUT: frame or context is null"
        );
    }

    /* Get current time */
    int64_t now_ms = 0;
    if (ctx->get_epoch_ms) {
        now_ms = ctx->get_epoch_ms();
    }

    ValidationResult r;

    /* ── Step 1: Version ──────────────────────────────── */
    r = validate_version(frame);
    if (!r.passed) return r;

    /* ── Step 2: Timestamp ────────────────────────────── */
    r = validate_timestamp(frame, now_ms);
    if (!r.passed) return r;

    /* ── Step 3: Payload Size ─────────────────────────── */
    r = validate_payload_size(frame);
    if (!r.passed) return r;

    /* ── Step 4: Nonce Uniqueness ─────────────────────── */
    r = validate_nonce(frame, &ctx->nonce_cache, now_ms);
    if (!r.passed) return r;

    /* ── Step 5: Payload Hash ─────────────────────────── */
    r = validate_payload_hash(frame);
    if (!r.passed) return r;

    /* ── Step 6: Sequence Monotonicity ────────────────── */
    r = validate_sequence(frame, &ctx->sequence);
    if (!r.passed) return r;

    /* ── Step 7: HMAC Signature ───────────────────────── */
    if (!ctx->secret_loaded) {
        return ValidationResult::fail(
            ValidationStep::SignatureCheck,
            "SECRET_NOT_LOADED: device secret unavailable"
        );
    }

    r = validate_signature(
        frame,
        ctx->device_secret, SecretLen,
        ctx->prev_secret, ctx->prev_secret_loaded
    );

    return r;
}

} /* namespace hxtp */
