/*
 * HXTP Embedded SDK v1.0.3
 * Cryptographic Operations — BearSSL Implementation (ESP8266)
 *
 * Implements the hxtp::crypto interface using ESP8266 Arduino Crypto.h
 * (which wraps BearSSL) for SHA-256 and HMAC-SHA256.
 *
 *
 * NO mbedTLS dependency. Uses only BearSSL (shipped with ESP8266 core).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifdef ESP8266

#include "Crypto.h"
#include "Config.h"
#include "HxtpCryptoInternal.h"
#include <cstring>

/* ESP8266 Arduino core Crypto.h — wraps BearSSL */
#include <Crypto.h>
#include <bearssl/bearssl.h>



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

Error sha256(const uint8_t* data, size_t len, uint8_t out[Sha256Len]) {
    br_sha256_context ctx;
    br_sha256_init(&ctx);
    br_sha256_update(&ctx, data, len);
    br_sha256_out(&ctx, out);
    return Error::OK;
}

Error sha256_hex(const char* str, size_t str_len, char out_hex[Sha256HexLen + 1]) {
    uint8_t hash[Sha256Len];
    sha256(reinterpret_cast<const uint8_t*>(str), str_len, hash);
    hex_encode(hash, Sha256Len, out_hex);
    return Error::OK;
}

/* ── HMAC-SHA256 (via ESP8266 Crypto.h → BearSSL) ──────────────────── */

Error hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[HmacLen]
) {
    br_hmac_key_context kc;
    br_hmac_context hc;

    br_hmac_key_init(&kc, &br_sha256_vtable, key, key_len);
    br_hmac_init(&hc, &kc, 32);
    br_hmac_update(&hc, data, data_len);
    br_hmac_out(&hc, out);

    return Error::OK;
}

/* ── Nonce Generation ───────────────────────────────────────────────── */

Error generate_nonce(char* out, size_t* out_len, bool (*rng)(uint8_t*, size_t)) {
    uint8_t raw[NonceRawMin];
    if (!rng(raw, NonceRawMin)) return Error::RNG_FAILED;
    if (!base64_encode(raw, NonceRawMin, out, MaxNonceLen + 1, out_len)) {
        return Error::RNG_FAILED;
    }
    return Error::OK;
}

/* ── UUID v4 Generation ─────────────────────────────────────────────── */

Error generate_uuid_v4(char out[37], bool (*rng)(uint8_t*, size_t)) {
    uint8_t raw[16];
    if (!rng(raw, 16)) return Error::RNG_FAILED;

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
    return Error::OK;
}

/* ── Ed25519 ────────────────────────────────────────────────────────── */

Error ed25519_keygen(
    uint8_t pub[Ed25519PubKeyLen],
    uint8_t priv[Ed25519PrivKeyLen],
    bool (*rng)(uint8_t*, size_t)
) {
    int ret = hxtp_crypto_sign_keypair(pub, priv, rng);
    return (ret == 0) ? Error::OK : Error::KEYGEN_FAILED;
}

Error ed25519_sign(
    const uint8_t* msg, size_t len,
    const uint8_t priv[Ed25519PrivKeyLen],
    const uint8_t pub[Ed25519PubKeyLen],
    uint8_t sig[Ed25519SigLen]
) {
    int ret = hxtp_crypto_sign_detached(sig, msg, len, priv, pub);
    return (ret == 0) ? Error::OK : Error::SIGN_FAILED;
}

Error ed25519_verify(
    const uint8_t* msg, size_t len,
    const uint8_t pub[Ed25519PubKeyLen],
    const uint8_t sig[Ed25519SigLen]
) {
    int ret = hxtp_crypto_sign_verify(sig, msg, len, pub);
    return (ret == 0) ? Error::OK : Error::VERIFY_FAILED;
}

} /* namespace crypto */
} /* namespace hxtp */

#endif /* ESP8266 */
