/*
 * HXTP Embedded SDK v1.0
 * 7-Step Validation Pipeline — Header
 *
 * Implements the FROZEN validation order:
 *   1. Version check
 *   2. Timestamp freshness (±300s, +60s skew)
 *   3. Payload size enforcement
 *   4. Nonce uniqueness (ring buffer)
 *   5. Payload SHA-256 verification
 *   6. Sequence monotonicity
 *   7. HMAC-SHA256 signature verification (constant-time)
 *
 * ANY failure → reject immediately. No fallback. No soft-fail.
 *
 * Platform-agnostic. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_VALIDATION_H
#define HXTP_VALIDATION_H

#include "hxtp_types.h"
#include "hxtp_errors.h"

namespace hxtp {

/* ── Nonce Ring Buffer (fixed-size, no heap) ────────────────────────── */

struct NonceEntry {
    char     nonce[HXTP_MAX_NONCE_LEN + 1];
    int64_t  timestamp_ms;         /* when inserted (epoch ms) */
};

struct NonceCache {
    NonceEntry entries[HXTP_NONCE_CACHE_SIZE];
    size_t     head;               /* next write position */
    size_t     count;              /* number of valid entries */

    void init();

    /**
     * Check if nonce is already in cache.
     * If not found, inserts it and returns false (not duplicate).
     * If found, returns true (DUPLICATE — reject).
     * Also evicts entries older than HXTP_NONCE_TTL_SEC.
     */
    bool check_and_insert(const char* nonce, int64_t now_ms);
};

/* ── Sequence Tracker ───────────────────────────────────────────────── */

struct SequenceTracker {
    int64_t  last_sequence;
    bool     initialized;

    void init() { last_sequence = -1; initialized = false; }

    /**
     * Check if incoming sequence is strictly greater than last.
     * Updates last_sequence on success.
     * @return true if valid (seq > last), false if violation
     */
    bool check_and_advance(int64_t seq);
};

/* ── Validation Context (all state needed for pipeline) ─────────────── */

struct ValidationContext {
    /* Device secret (binary, 32 bytes) — loaded from NVS */
    uint8_t  device_secret[HXTP_SECRET_LEN];
    bool     secret_loaded;

    /* Previous device secret (for rotation window) */
    uint8_t  prev_secret[HXTP_SECRET_LEN];
    bool     prev_secret_loaded;

    /* Nonce cache */
    NonceCache nonce_cache;

    /* Per-client sequence tracker.
     * On an embedded device there is typically one client (the cloud).
     * We track a single sequence per device for simplicity. */
    SequenceTracker sequence;

    /* Platform time provider */
    int64_t (*get_epoch_ms)(void);

    /* Expected device_id for this device */
    char    device_id[HXTP_DEVICE_ID_LEN + 1];
    char    tenant_id[HXTP_UUID_LEN + 1];

    void init();
};

/* ── Validation Pipeline ────────────────────────────────────────────── */

/**
 * Run the 7-step validation pipeline on a parsed inbound frame.
 *
 * @param frame   Parsed inbound frame (from frame_decode + JSON parse)
 * @param ctx     Validation context with secrets, nonce cache, etc.
 * @return        HxtpValidationResult — .passed == true if all 7 steps pass
 */
HxtpValidationResult validate_message(
    const HxtpInboundFrame* frame,
    ValidationContext* ctx
);

/* ── Individual Steps (exposed for testing) ─────────────────────────── */

HxtpValidationResult validate_version(const HxtpInboundFrame* frame);
HxtpValidationResult validate_timestamp(const HxtpInboundFrame* frame, int64_t now_ms);
HxtpValidationResult validate_payload_size(const HxtpInboundFrame* frame);
HxtpValidationResult validate_nonce(const HxtpInboundFrame* frame, NonceCache* cache, int64_t now_ms);
HxtpValidationResult validate_payload_hash(const HxtpInboundFrame* frame);
HxtpValidationResult validate_sequence(const HxtpInboundFrame* frame, SequenceTracker* tracker);
HxtpValidationResult validate_signature(
    const HxtpInboundFrame* frame,
    const uint8_t* secret, size_t secret_len,
    const uint8_t* prev_secret, bool has_prev
);

/* ── Canonical String Builder ───────────────────────────────────────── */

/**
 * Build the canonical string for signature computation.
 * FROZEN FORMAT: version|message_type|device_id|tenant_id|timestamp|message_id|nonce
 *
 * @param hdr        Parsed message header
 * @param out        Output buffer
 * @param out_cap    Buffer capacity
 * @param out_len    Receives actual length
 * @return           true on success, false if buffer too small
 */
bool build_canonical_string(
    const HxtpMessageHeader* hdr,
    char* out,
    size_t out_cap,
    size_t* out_len
);

} /* namespace hxtp */

#endif /* HXTP_VALIDATION_H */
