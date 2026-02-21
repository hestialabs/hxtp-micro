/*
 * HXTP Embedded SDK v1.0
 * Cryptographic Operations — BearSSL Implementation (ESP8266)
 *
 * Implements the hxtp::crypto interface using ESP8266 Arduino Crypto.h
 * (which wraps BearSSL) for SHA-256 and HMAC-SHA256.
 *
 * AES-256-GCM is available via raw BearSSL API (bearssl/bearssl_aead.h)
 * but disabled by default in HXTP_CONSTRAINED mode to save stack.
 *
 * NO mbedTLS dependency. Uses only BearSSL (shipped with ESP8266 core).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifdef ESP8266

#include "HXTPCrypto.h"
#include "Config.h"
#include <cstring>

/* ESP8266 Arduino core Crypto.h — wraps BearSSL */
#include <Crypto.h>

/* Raw BearSSL headers for GCM (if enabled) */
#if HXTP_FEATURE_AES_GCM
#include <bearssl/bearssl_block.h>
#include <bearssl/bearssl_aead.h>
#endif

namespace hxtp {
namespace crypto {

/* ── Hex lookup ─────────────────────────────────────────────────────── */

static const char HEX_TABLE[] = "0123456789abcdef";

void hex_encode(const uint8_t* in, size_t in_len, char* out) {
    for (size_t i = 0; i < in_len; ++i) {
        out[i * 2]     = HEX_TABLE[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX_TABLE[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
}

static inline uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0xFF;
}

bool hex_decode(const char* hex, size_t hex_len, uint8_t* out, size_t* out_len) {
    if (hex_len % 2 != 0) return false;
    size_t n = hex_len / 2;
    for (size_t i = 0; i < n; ++i) {
        uint8_t hi = hex_nibble(hex[i * 2]);
        uint8_t lo = hex_nibble(hex[i * 2 + 1]);
        if (hi == 0xFF || lo == 0xFF) return false;
        out[i] = (hi << 4) | lo;
    }
    *out_len = n;
    return true;
}

/* ── Base64 ─────────────────────────────────────────────────────────── */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool base64_encode(const uint8_t* in, size_t in_len, char* out, size_t out_cap, size_t* out_len) {
    size_t needed = ((in_len + 2) / 3) * 4;
    if (needed + 1 > out_cap) return false;

    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t triple = (static_cast<uint32_t>(in[i]) << 16);
        if (i + 1 < in_len) triple |= (static_cast<uint32_t>(in[i + 1]) << 8);
        if (i + 2 < in_len) triple |= (static_cast<uint32_t>(in[i + 2]));

        out[j++] = B64_TABLE[(triple >> 18) & 0x3F];
        out[j++] = B64_TABLE[(triple >> 12) & 0x3F];
        out[j++] = (i + 1 < in_len) ? B64_TABLE[(triple >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < in_len) ? B64_TABLE[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    *out_len = j;
    return true;
}

/* ── SHA-256 (via ESP8266 Crypto.h → BearSSL) ──────────────────────── */

HxtpError sha256(const uint8_t* data, size_t len, uint8_t out[HXTP_SHA256_LEN]) {
    /*
     * experimental::crypto::SHA256::hash(data, dataLength, resultArray)
     * Returns pointer to resultArray on success.
     */
    void* result = experimental::crypto::SHA256::hash(data, len, out);
    return result ? HxtpError::OK : HxtpError::SHA256_COMPUTE_FAILED;
}

HxtpError sha256_hex(const char* str, size_t str_len, char out_hex[HXTP_SHA256_HEX_LEN + 1]) {
    uint8_t hash[HXTP_SHA256_LEN];
    HxtpError err = sha256(reinterpret_cast<const uint8_t*>(str), str_len, hash);
    if (err != HxtpError::OK) return err;
    hex_encode(hash, HXTP_SHA256_LEN, out_hex);
    return HxtpError::OK;
}

/* ── HMAC-SHA256 (via ESP8266 Crypto.h → BearSSL) ──────────────────── */

HxtpError hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HXTP_HMAC_LEN]
) {
    /*
     * experimental::crypto::SHA256::hmac(data, dataLength, hashKey, hashKeyLength,
     *                                    resultArray, outputLength)
     * outputLength=0 means use NATURAL_LENGTH (32).
     */
    void* result = experimental::crypto::SHA256::hmac(
        data, data_len,
        key, key_len,
        out, 0  /* 0 = full NATURAL_LENGTH = 32 bytes */
    );
    return result ? HxtpError::OK : HxtpError::HMAC_COMPUTE_FAILED;
}

HxtpError hmac_sha256_hex(
    const uint8_t* key, size_t key_len,
    const char* data, size_t data_len,
    char out_hex[HXTP_HMAC_HEX_LEN + 1]
) {
    uint8_t mac[HXTP_HMAC_LEN];
    HxtpError err = hmac_sha256(key, key_len,
                                 reinterpret_cast<const uint8_t*>(data), data_len,
                                 mac);
    if (err != HxtpError::OK) return err;
    hex_encode(mac, HXTP_HMAC_LEN, out_hex);
    return HxtpError::OK;
}

/* ── Constant-Time Compare ──────────────────────────────────────────── */

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

bool constant_time_hex_equal(const char* a, const char* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t ca = static_cast<uint8_t>(a[i]);
        uint8_t cb = static_cast<uint8_t>(b[i]);
        /* Fold A-F to a-f: if in [0x41..0x5A], set bit 5 */
        ca |= ((ca >= 'A' && ca <= 'Z') ? 0x20 : 0x00);
        cb |= ((cb >= 'A' && cb <= 'Z') ? 0x20 : 0x00);
        diff |= ca ^ cb;
    }
    return diff == 0;
}

/* ── AES-256-GCM (via raw BearSSL API) ──────────────────────────────── */

#if HXTP_FEATURE_AES_GCM

HxtpError aes256_gcm_decrypt(
    const uint8_t key[HXTP_AES_KEY_LEN],
    const uint8_t* input, size_t input_len,
    uint8_t* output, size_t* output_len
) {
    /* Format: IV[12] + CIPHERTEXT[n] + TAG[16] */
    const size_t overhead = HXTP_AES_GCM_IV_LEN + HXTP_AES_GCM_TAG_LEN;
    if (input_len < overhead) return HxtpError::AES_DECRYPT_FAILED;

    const uint8_t* iv   = input;
    size_t ct_len       = input_len - overhead;
    const uint8_t* ct   = input + HXTP_AES_GCM_IV_LEN;
    const uint8_t* tag  = input + HXTP_AES_GCM_IV_LEN + ct_len;

    /* BearSSL AES-256-GCM via constant-time AES engine */
    br_aes_ct_ctr_keys aes_ctx;
    br_aes_ct_ctr_init(&aes_ctx, key, HXTP_AES_KEY_LEN);

    br_gcm_context gcm;
    br_gcm_init(&gcm, &aes_ctx.vtable, br_ghash_ctmul32);

    br_gcm_reset(&gcm, iv, HXTP_AES_GCM_IV_LEN);
    /* No AAD */
    br_gcm_flip(&gcm);

    /* Decrypt in-place: copy ciphertext to output first */
    memcpy(output, ct, ct_len);
    br_gcm_run(&gcm, 0 /* decrypt */, output, ct_len);

    /* Verify tag */
    if (!br_gcm_check_tag(&gcm, tag)) {
        memset(output, 0, ct_len); /* Clear on failure */
        return HxtpError::AES_DECRYPT_FAILED;
    }

    *output_len = ct_len;
    return HxtpError::OK;
}

HxtpError aes256_gcm_encrypt(
    const uint8_t key[HXTP_AES_KEY_LEN],
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* output, size_t* output_len,
    bool (*rng)(uint8_t*, size_t)
) {
    /* Output: IV[12] + CIPHERTEXT[pt_len] + TAG[16] */
    uint8_t iv[HXTP_AES_GCM_IV_LEN];
    if (!rng(iv, HXTP_AES_GCM_IV_LEN)) return HxtpError::RNG_FAILED;

    br_aes_ct_ctr_keys aes_ctx;
    br_aes_ct_ctr_init(&aes_ctx, key, HXTP_AES_KEY_LEN);

    br_gcm_context gcm;
    br_gcm_init(&gcm, &aes_ctx.vtable, br_ghash_ctmul32);

    br_gcm_reset(&gcm, iv, HXTP_AES_GCM_IV_LEN);
    /* No AAD */
    br_gcm_flip(&gcm);

    /* Encrypt: copy plaintext to output + IV offset, encrypt in-place */
    uint8_t* ct_out = output + HXTP_AES_GCM_IV_LEN;
    memcpy(ct_out, plaintext, pt_len);
    br_gcm_run(&gcm, 1 /* encrypt */, ct_out, pt_len);

    /* Get tag */
    uint8_t tag[HXTP_AES_GCM_TAG_LEN];
    br_gcm_get_tag(&gcm, tag);

    /* Write IV at beginning */
    memcpy(output, iv, HXTP_AES_GCM_IV_LEN);
    /* Write tag at end */
    memcpy(output + HXTP_AES_GCM_IV_LEN + pt_len, tag, HXTP_AES_GCM_TAG_LEN);

    *output_len = HXTP_AES_GCM_IV_LEN + pt_len + HXTP_AES_GCM_TAG_LEN;
    return HxtpError::OK;
}

#endif /* HXTP_FEATURE_AES_GCM */

/* ── Nonce Generation ───────────────────────────────────────────────── */

HxtpError generate_nonce(char* out, size_t* out_len, bool (*rng)(uint8_t*, size_t)) {
    uint8_t raw[HXTP_NONCE_RAW_MIN];
    if (!rng(raw, HXTP_NONCE_RAW_MIN)) return HxtpError::RNG_FAILED;
    if (!base64_encode(raw, HXTP_NONCE_RAW_MIN, out, HXTP_MAX_NONCE_LEN + 1, out_len)) {
        return HxtpError::RNG_FAILED;
    }
    return HxtpError::OK;
}

/* ── UUID v4 Generation ─────────────────────────────────────────────── */

HxtpError generate_uuid_v4(char out[37], bool (*rng)(uint8_t*, size_t)) {
    uint8_t raw[16];
    if (!rng(raw, 16)) return HxtpError::RNG_FAILED;

    /* Set version 4 */
    raw[6] = (raw[6] & 0x0F) | 0x40;
    /* Set variant 10 */
    raw[8] = (raw[8] & 0x3F) | 0x80;

    /* Format: 8-4-4-4-12 */
    static const int positions[] = { 0,1,2,3, -1, 4,5, -1, 6,7, -1, 8,9, -1, 10,11,12,13,14,15 };
    int oi = 0;
    for (int i = 0; i < 20; ++i) {
        if (positions[i] == -1) {
            out[oi++] = '-';
        } else {
            uint8_t b = raw[positions[i]];
            out[oi++] = HEX_TABLE[(b >> 4) & 0x0F];
            out[oi++] = HEX_TABLE[b & 0x0F];
        }
    }
    out[oi] = '\0';
    return HxtpError::OK;
}

} /* namespace crypto */
} /* namespace hxtp */

#endif /* ESP8266 */
