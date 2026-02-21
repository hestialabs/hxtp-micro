/*
 * HXTP Embedded SDK v1.0
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
#include "HXTPCrypto.h"
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

    const int64_t ttl_ms = static_cast<int64_t>(HXTP_NONCE_TTL_SEC) * 1000;

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
    if (nlen > HXTP_MAX_NONCE_LEN) nlen = HXTP_MAX_NONCE_LEN;
    memcpy(slot.nonce, nonce, nlen);
    slot.nonce[nlen]  = '\0';
    slot.timestamp_ms = now_ms;

    head = (head + 1) % HXTP_NONCE_CACHE_SIZE;
    if (count < HXTP_NONCE_CACHE_SIZE) ++count;

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

bool build_canonical_string(
    const HxtpMessageHeader* hdr,
    char* out,
    size_t out_cap,
    size_t* out_len)
{
    if (!hdr || !out || out_cap == 0) return false;

    /* FROZEN FORMAT: version|message_type|device_id|tenant_id|timestamp|message_id|nonce
     *
     * Matches server Canonical.ts exactly:
     *   String(Msg.version), String(Msg.message_type), String(Msg.device_id),
     *   String(Msg.tenant_id), String(Msg.timestamp), String(Msg.message_id),
     *   String(Msg.nonce)
     */

    /* Timestamp → string (decimal).  Server uses String(timestamp) which
     * produces the decimal representation of the numeric value. */
    char ts_buf[24];
    int ts_len = snprintf(ts_buf, sizeof(ts_buf), "%lld",
                          static_cast<long long>(hdr->timestamp));
    if (ts_len < 0) ts_len = 0;

    /* Calculate required length */
    size_t required =
        hdr->version.len
        + 1  /* | */
        + hdr->message_type.len
        + 1
        + hdr->device_id.len
        + 1
        + hdr->tenant_id.len
        + 1
        + static_cast<size_t>(ts_len)
        + 1
        + hdr->message_id.len
        + 1
        + hdr->nonce.len
        + 1; /* null terminator */

    if (required > out_cap) {
        *out_len = 0;
        return false;
    }

    /* Build the canonical string with pipe separators */
    char* p = out;

    memcpy(p, hdr->version.c_str(), hdr->version.len);     p += hdr->version.len;
    *p++ = HXTP_CANONICAL_SEP;

    memcpy(p, hdr->message_type.c_str(), hdr->message_type.len); p += hdr->message_type.len;
    *p++ = HXTP_CANONICAL_SEP;

    memcpy(p, hdr->device_id.c_str(), hdr->device_id.len); p += hdr->device_id.len;
    *p++ = HXTP_CANONICAL_SEP;

    memcpy(p, hdr->tenant_id.c_str(), hdr->tenant_id.len); p += hdr->tenant_id.len;
    *p++ = HXTP_CANONICAL_SEP;

    memcpy(p, ts_buf, static_cast<size_t>(ts_len));         p += ts_len;
    *p++ = HXTP_CANONICAL_SEP;

    memcpy(p, hdr->message_id.c_str(), hdr->message_id.len); p += hdr->message_id.len;
    *p++ = HXTP_CANONICAL_SEP;

    memcpy(p, hdr->nonce.c_str(), hdr->nonce.len);         p += hdr->nonce.len;

    *p = '\0';
    *out_len = static_cast<size_t>(p - out);
    return true;
}

/* ════════════════════════════════════════════════════════════════════
 *  Individual Validation Steps
 * ════════════════════════════════════════════════════════════════════ */

/* ── Step 1: Version Check ──────────────────────────────────────── */

HxtpValidationResult validate_version(const HxtpInboundFrame* frame) {
    if (!frame->header.version.equals(HXTP_VERSION_STRING)) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::VERSION_CHECK,
            "VERSION_MISMATCH: unsupported protocol version"
        );
    }
    return HxtpValidationResult::ok();
}

/* ── Step 2: Timestamp Freshness ─────────────────────────────────── */

HxtpValidationResult validate_timestamp(const HxtpInboundFrame* frame, int64_t now_ms) {
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

    /* Too old */
    if (age_sec > static_cast<int64_t>(HXTP_MAX_MESSAGE_AGE_SEC)) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::TIMESTAMP_CHECK,
            "TIMESTAMP_EXPIRED: message too old"
        );
    }

    /* Too far in the future (clock drift protection) */
    if (ts_sec > now_sec + static_cast<int64_t>(HXTP_TIMESTAMP_SKEW_SEC)) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::TIMESTAMP_CHECK,
            "TIMESTAMP_FUTURE: message timestamp from future"
        );
    }

    return HxtpValidationResult::ok();
}

/* ── Step 3: Payload Size ────────────────────────────────────────── */

HxtpValidationResult validate_payload_size(const HxtpInboundFrame* frame) {
    if (frame->json_len > HXTP_MAX_PAYLOAD_BYTES) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::PAYLOAD_SIZE_CHECK,
            "PAYLOAD_TOO_LARGE: exceeds 16KB limit"
        );
    }
    return HxtpValidationResult::ok();
}

/* ── Step 4: Nonce Uniqueness ────────────────────────────────────── */

HxtpValidationResult validate_nonce(
    const HxtpInboundFrame* frame,
    NonceCache* cache,
    int64_t now_ms)
{
    if (frame->header.nonce.empty()) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::NONCE_CHECK,
            "NONCE_MISSING: nonce field is empty"
        );
    }

    bool is_dup = cache->check_and_insert(frame->header.nonce.c_str(), now_ms);
    if (is_dup) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::NONCE_CHECK,
            "NONCE_REUSED: replay attack detected"
        );
    }

    return HxtpValidationResult::ok();
}

/* ── Step 5: Payload Hash ────────────────────────────────────────── */

HxtpValidationResult validate_payload_hash(const HxtpInboundFrame* frame) {
    /* If no payload_hash provided, skip (matches server behavior —
     * server checks "if (Msg.payload_hash)") */
    if (frame->header.payload_hash.empty()) {
        return HxtpValidationResult::ok();
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

    char computed_hex[HXTP_SHA256_HEX_LEN + 1];
    HxtpError err = crypto::sha256_hex(params, plen, computed_hex);
    if (err != HxtpError::OK) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::PAYLOAD_HASH_CHECK,
            "HASH_COMPUTE_FAILED: could not compute SHA-256"
        );
    }

    /* Compare hashes — NOT constant-time (payload hash is not a secret) */
    if (strcmp(computed_hex, frame->header.payload_hash.c_str()) != 0) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::PAYLOAD_HASH_CHECK,
            "HASH_MISMATCH: payload hash does not match"
        );
    }

    return HxtpValidationResult::ok();
}

/* ── Step 6: Sequence Monotonicity ───────────────────────────────── */

HxtpValidationResult validate_sequence(
    const HxtpInboundFrame* frame,
    SequenceTracker* tracker)
{
    /* If no sequence_number provided, skip (optional field) */
    if (frame->header.sequence_number < 0) {
        return HxtpValidationResult::ok();
    }

    bool valid = tracker->check_and_advance(frame->header.sequence_number);
    if (!valid) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::SEQUENCE_CHECK,
            "SEQUENCE_VIOLATION: out-of-order or duplicate sequence"
        );
    }

    return HxtpValidationResult::ok();
}

/* ── Step 7: HMAC-SHA256 Signature ───────────────────────────────── */

HxtpValidationResult validate_signature(
    const HxtpInboundFrame* frame,
    const uint8_t* secret, size_t secret_len,
    const uint8_t* prev_secret, bool has_prev)
{
    if (frame->header.signature.empty()) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::SIGNATURE_CHECK,
            "SIGNATURE_MISSING: signature field is empty"
        );
    }

    /* Build canonical string */
    char canonical[512];
    size_t canonical_len = 0;
    if (!build_canonical_string(&frame->header, canonical, sizeof(canonical), &canonical_len)) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::SIGNATURE_CHECK,
            "CANONICAL_BUILD_FAILED: could not build canonical string"
        );
    }

    /* Compute HMAC-SHA256 with primary secret */
    char computed_hex[HXTP_HMAC_HEX_LEN + 1];
    HxtpError err = crypto::hmac_sha256_hex(
        secret, secret_len,
        canonical, canonical_len,
        computed_hex
    );
    if (err != HxtpError::OK) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::SIGNATURE_CHECK,
            "HMAC_COMPUTE_FAILED: could not compute HMAC"
        );
    }

    /* Constant-time compare (CRITICAL — timing side-channel protection) */
    if (crypto::constant_time_hex_equal(
            computed_hex,
            frame->header.signature.c_str(),
            HXTP_HMAC_HEX_LEN))
    {
        return HxtpValidationResult::ok();
    }

    /* ── Fallback: try previous secret (key rotation window) ─────── */
    if (has_prev && prev_secret) {
        err = crypto::hmac_sha256_hex(
            prev_secret, secret_len,
            canonical, canonical_len,
            computed_hex
        );
        if (err != HxtpError::OK) {
            return HxtpValidationResult::fail(
                HxtpValidationStep::SIGNATURE_CHECK,
                "HMAC_COMPUTE_FAILED: previous secret HMAC failed"
            );
        }

        if (crypto::constant_time_hex_equal(
                computed_hex,
                frame->header.signature.c_str(),
                HXTP_HMAC_HEX_LEN))
        {
            /* Verified with previous secret — rotation in progress */
            return HxtpValidationResult::ok();
        }
    }

    /* Both secrets failed */
    return HxtpValidationResult::fail(
        HxtpValidationStep::SIGNATURE_CHECK,
        "SIGNATURE_INVALID: HMAC verification failed"
    );
}

/* ════════════════════════════════════════════════════════════════════
 *  Full Validation Pipeline
 * ════════════════════════════════════════════════════════════════════ */

HxtpValidationResult validate_message(
    const HxtpInboundFrame* frame,
    ValidationContext* ctx)
{
    if (!frame || !ctx) {
        return HxtpValidationResult::fail(
            HxtpValidationStep::VERSION_CHECK,
            "NULL_INPUT: frame or context is null"
        );
    }

    /* Get current time */
    int64_t now_ms = 0;
    if (ctx->get_epoch_ms) {
        now_ms = ctx->get_epoch_ms();
    }

    HxtpValidationResult r;

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
        return HxtpValidationResult::fail(
            HxtpValidationStep::SIGNATURE_CHECK,
            "SECRET_NOT_LOADED: device secret unavailable"
        );
    }

    r = validate_signature(
        frame,
        ctx->device_secret, HXTP_SECRET_LEN,
        ctx->prev_secret, ctx->prev_secret_loaded
    );

    return r;
}

} /* namespace hxtp */
