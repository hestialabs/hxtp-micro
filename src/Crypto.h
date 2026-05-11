/*
 * HXTP Embedded SDK v1.0.3
 * Cryptographic Operations — Header
 *
 * Provides SHA-256, HMAC-SHA256, base64 encode, hex encode/decode,
 * nonce generation, UUID v4, and Ed25519 signing/verification.
 *
 * Implementation uses mbedTLS (ESP32) or pluggable backend.
 * Platform-agnostic header. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "Types.h"
#include "Errors.h"
#include "Config.h"

namespace hxtp {
namespace crypto {

/* ── SHA-256 ────────────────────────────────────────────────────────── */

/**
 * Compute SHA-256 hash of input data.
 * @param data     Input bytes
 * @param len      Input length
 * @param out      Output buffer (32 bytes)
 * @return         Error::OK or SHA256_COMPUTE_FAILED
 */
Error sha256(const uint8_t* data, size_t len, uint8_t out[Sha256Len]);

/**
 * Compute SHA-256 of a string and write hex digest.
 * @param str      Null-terminated input string
 * @param out_hex  Output buffer (64 chars + null terminator, so ≥65)
 * @return         Error::OK or error
 */
Error sha256_hex(const char* str, size_t str_len, char out_hex[Sha256HexLen + 1]);

/* ── HMAC-SHA256 ────────────────────────────────────────────────────── */

/**
 * Compute HMAC-SHA256.
 * @param key      Key bytes
 * @param key_len  Key length
 * @param data     Data bytes
 * @param data_len Data length
 * @param out      Output buffer (32 bytes)
 * @return         Error::OK or HMAC_COMPUTE_FAILED
 */
Error hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HmacLen]
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
 * @param out      Output buffer (must be >= MaxNonceLen + 1)
 * @param out_len  Receives encoded length
 * @param rng      Platform RNG function
 * @return         Error::OK or RNG_FAILED
 */
Error generate_nonce(char* out, size_t* out_len, bool (*rng)(uint8_t*, size_t));

/* ── UUID v4 Generation ─────────────────────────────────────────────── */

/**
 * Generate a UUID v4 string (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
 * @param out  Output buffer (must be >= 37 bytes)
 * @param rng  Platform RNG function
 * @return     Error::OK or RNG_FAILED
 */
Error generate_uuid_v4(char out[37], bool (*rng)(uint8_t*, size_t));

/* ── Ed25519 Identity ───────────────────────────────────────────────── */

/**
 * Generate an Ed25519 keypair.
 * @param pub   Output public key (32 bytes)
 * @param priv  Output private key seed (32 bytes)
 * @param rng   Platform RNG function
 * @return      Error::OK or RNG_FAILED
 */
Error ed25519_keygen(
    uint8_t pub[Ed25519PubKeyLen],
    uint8_t priv[Ed25519PrivKeyLen],
    bool (*rng)(uint8_t*, size_t)
);

/**
 * Sign a message using Ed25519.
 * @param msg       Message data
 * @param len       Message length
 * @param priv      Private key seed (32 bytes)
 * @param pub       Public key (32 bytes)
 * @param sig       Output signature (64 bytes)
 * @return          Error::OK or SIGN_FAILED
 */
Error ed25519_sign(
    const uint8_t* msg, size_t len,
    const uint8_t priv[Ed25519PrivKeyLen],
    const uint8_t pub[Ed25519PubKeyLen],
    uint8_t sig[Ed25519SigLen]
);

/**
 * Verify an Ed25519 signature.
 * @param msg       Message data
 * @param len       Message length
 * @param pub       Public key (32 bytes)
 * @param sig       Signature (64 bytes)
 * @return          Error::OK or SIGNATURE_INVALID
 */
Error ed25519_verify(
    const uint8_t* msg, size_t len,
    const uint8_t pub[Ed25519PubKeyLen],
    const uint8_t sig[Ed25519SigLen]
);

/**
 * Sign a message and produce hex signature.
 */
Error ed25519_sign_hex(
    const char* msg, size_t len,
    const uint8_t priv[Ed25519PrivKeyLen],
    const uint8_t pub[Ed25519PubKeyLen],
    char sig_hex[Ed25519SigHexLen + 1]
);

/**
 * Verify a hex signature.
 */
Error ed25519_verify_hex(
    const char* msg, size_t len,
    const uint8_t pub[Ed25519PubKeyLen],
    const char sig_hex[Ed25519SigHexLen + 1]
);

} /* namespace crypto */
} /* namespace hxtp */

#endif /* CRYPTO_H */
