/*
 * HXTP Embedded SDK v1.0
 * Cryptographic Operations — Header
 *
 * Provides SHA-256, HMAC-SHA256, AES-256-GCM, constant-time compare,
 * base64 encode, hex encode/decode, and nonce generation.
 *
 * Implementation uses mbedTLS (ESP32) or pluggable backend.
 * Platform-agnostic header. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_CRYPTO_H
#define HXTP_CRYPTO_H

#include "hxtp_types.h"
#include "hxtp_errors.h"

namespace hxtp {
namespace crypto {

/* ── SHA-256 ────────────────────────────────────────────────────────── */

/**
 * Compute SHA-256 hash of input data.
 * @param data     Input bytes
 * @param len      Input length
 * @param out      Output buffer (32 bytes)
 * @return         HxtpError::OK or SHA256_COMPUTE_FAILED
 */
HxtpError sha256(const uint8_t* data, size_t len, uint8_t out[HXTP_SHA256_LEN]);

/**
 * Compute SHA-256 of a string and write hex digest.
 * @param str      Null-terminated input string
 * @param out_hex  Output buffer (64 chars + null terminator, so ≥65)
 * @return         HxtpError::OK or error
 */
HxtpError sha256_hex(const char* str, size_t str_len, char out_hex[HXTP_SHA256_HEX_LEN + 1]);

/* ── HMAC-SHA256 ────────────────────────────────────────────────────── */

/**
 * Compute HMAC-SHA256.
 * @param key      Key bytes
 * @param key_len  Key length
 * @param data     Data bytes
 * @param data_len Data length
 * @param out      Output buffer (32 bytes)
 * @return         HxtpError::OK or HMAC_COMPUTE_FAILED
 */
HxtpError hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HXTP_HMAC_LEN]
);

/**
 * Compute HMAC-SHA256 and produce hex digest.
 */
HxtpError hmac_sha256_hex(
    const uint8_t* key, size_t key_len,
    const char* data, size_t data_len,
    char out_hex[HXTP_HMAC_HEX_LEN + 1]
);

/* ── Constant-Time Compare ──────────────────────────────────────────── */

/**
 * Constant-time comparison of two byte buffers.
 * Returns true if identical, false otherwise.
 * Timing does not depend on where (or if) the buffers differ.
 */
bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

/**
 * Constant-time comparison of two hex strings (case-insensitive).
 */
bool constant_time_hex_equal(const char* a, const char* b, size_t len);

/* ── AES-256-GCM ────────────────────────────────────────────────────── */

/**
 * Decrypt AES-256-GCM. Input format: IV[12] + CIPHERTEXT[n] + TAG[16]
 * @param key         32-byte key
 * @param input       IV + ciphertext + tag
 * @param input_len   Total input length (must be >= 28)
 * @param output      Plaintext output buffer (must be >= input_len - 28)
 * @param output_len  Receives plaintext length
 * @return            HxtpError::OK or AES_DECRYPT_FAILED
 */
HxtpError aes256_gcm_decrypt(
    const uint8_t key[HXTP_AES_KEY_LEN],
    const uint8_t* input, size_t input_len,
    uint8_t* output, size_t* output_len
);

/**
 * Encrypt AES-256-GCM. Output format: IV[12] + CIPHERTEXT[n] + TAG[16]
 * IV is generated from platform RNG.
 * @param key           32-byte key
 * @param plaintext     Input data
 * @param pt_len        Plaintext length
 * @param output        Output buffer (must be >= pt_len + 28)
 * @param output_len    Receives total output length
 * @param rng           Platform RNG function
 * @return              HxtpError::OK or error
 */
HxtpError aes256_gcm_encrypt(
    const uint8_t key[HXTP_AES_KEY_LEN],
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* output, size_t* output_len,
    bool (*rng)(uint8_t*, size_t)
);

/* ── Hex Encode/Decode ──────────────────────────────────────────────── */

/**
 * Encode binary to lowercase hex.
 * @param in       Input bytes
 * @param in_len   Input length
 * @param out      Output buffer (must be >= in_len * 2 + 1)
 */
void hex_encode(const uint8_t* in, size_t in_len, char* out);

/**
 * Decode hex string to binary.
 * @param hex      Hex string (must be even length)
 * @param out      Output bytes
 * @param out_len  Receives number of bytes decoded
 * @return         true on success
 */
bool hex_decode(const char* hex, size_t hex_len, uint8_t* out, size_t* out_len);

/* ── Base64 Encode ──────────────────────────────────────────────────── */

/**
 * Encode binary to base64.
 * @param in       Input bytes
 * @param in_len   Input length
 * @param out      Output buffer
 * @param out_cap  Output capacity
 * @param out_len  Receives encoded length (excluding null)
 * @return         true on success
 */
bool base64_encode(const uint8_t* in, size_t in_len, char* out, size_t out_cap, size_t* out_len);

/**
 * Generate a random nonce, base64 encoded.
 * @param out      Output buffer (must be >= HXTP_MAX_NONCE_LEN + 1)
 * @param out_len  Receives encoded length
 * @param rng      Platform RNG function
 * @return         HxtpError::OK or RNG_FAILED
 */
HxtpError generate_nonce(char* out, size_t* out_len, bool (*rng)(uint8_t*, size_t));

/* ── UUID v4 Generation ─────────────────────────────────────────────── */

/**
 * Generate a UUID v4 string (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
 * @param out  Output buffer (must be >= 37 bytes)
 * @param rng  Platform RNG function
 * @return     HxtpError::OK or RNG_FAILED
 */
HxtpError generate_uuid_v4(char out[37], bool (*rng)(uint8_t*, size_t));

} /* namespace crypto */
} /* namespace hxtp */

#endif /* HXTP_CRYPTO_H */
