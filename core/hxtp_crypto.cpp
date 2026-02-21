/*
 * HXTP Embedded SDK v1.0
 * Cryptographic Operations — Implementation
 *
 * Uses mbedTLS for all crypto (available on ESP32 and ESP8266).
 * NO Arduino includes. Platform RNG injected via function pointer.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "hxtp_crypto.h"
#include <cstring>

/* ── mbedTLS headers ────────────────────────────────────────────────── */

#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

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

/* ── SHA-256 ────────────────────────────────────────────────────────── */

HxtpError sha256(const uint8_t* data, size_t len, uint8_t out[HXTP_SHA256_LEN]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts(&ctx, 0); /* 0 = SHA-256, not SHA-224 */
    if (ret != 0) { mbedtls_sha256_free(&ctx); return HxtpError::SHA256_COMPUTE_FAILED; }

    ret = mbedtls_sha256_update(&ctx, data, len);
    if (ret != 0) { mbedtls_sha256_free(&ctx); return HxtpError::SHA256_COMPUTE_FAILED; }

    ret = mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
    return (ret == 0) ? HxtpError::OK : HxtpError::SHA256_COMPUTE_FAILED;
}

HxtpError sha256_hex(const char* str, size_t str_len, char out_hex[HXTP_SHA256_HEX_LEN + 1]) {
    uint8_t hash[HXTP_SHA256_LEN];
    HxtpError err = sha256(reinterpret_cast<const uint8_t*>(str), str_len, hash);
    if (err != HxtpError::OK) return err;
    hex_encode(hash, HXTP_SHA256_LEN, out_hex);
    return HxtpError::OK;
}

/* ── HMAC-SHA256 ────────────────────────────────────────────────────── */

HxtpError hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HXTP_HMAC_LEN]
) {
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return HxtpError::HMAC_COMPUTE_FAILED;

    int ret = mbedtls_md_hmac(md_info, key, key_len, data, data_len, out);
    return (ret == 0) ? HxtpError::OK : HxtpError::HMAC_COMPUTE_FAILED;
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
    /*
     * Compare hex strings in constant time.
     * We fold to lowercase and XOR — timing does not depend on
     * position of first difference.
     */
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

/* ── AES-256-GCM ────────────────────────────────────────────────────── */

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

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return HxtpError::AES_DECRYPT_FAILED;
    }

    ret = mbedtls_gcm_auth_decrypt(
        &ctx, ct_len,
        iv, HXTP_AES_GCM_IV_LEN,
        nullptr, 0,       /* no additional data */
        tag, HXTP_AES_GCM_TAG_LEN,
        ct, output
    );

    mbedtls_gcm_free(&ctx);

    if (ret != 0) return HxtpError::AES_DECRYPT_FAILED;
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

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return HxtpError::CRYPTO_INIT_FAILED;
    }

    uint8_t tag[HXTP_AES_GCM_TAG_LEN];
    uint8_t* ct_out = output + HXTP_AES_GCM_IV_LEN;

    ret = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT, pt_len,
        iv, HXTP_AES_GCM_IV_LEN,
        nullptr, 0,       /* no additional data */
        plaintext, ct_out,
        HXTP_AES_GCM_TAG_LEN, tag
    );

    mbedtls_gcm_free(&ctx);

    if (ret != 0) return HxtpError::CRYPTO_INIT_FAILED;

    /* Write IV at beginning */
    memcpy(output, iv, HXTP_AES_GCM_IV_LEN);
    /* Write tag at end */
    memcpy(output + HXTP_AES_GCM_IV_LEN + pt_len, tag, HXTP_AES_GCM_TAG_LEN);

    *output_len = HXTP_AES_GCM_IV_LEN + pt_len + HXTP_AES_GCM_TAG_LEN;
    return HxtpError::OK;
}

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
