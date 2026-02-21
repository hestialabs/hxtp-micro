/*
 * HXTP Embedded SDK v1.0.0
 * Compile-Time Feature Configuration
 *
 * ════════════════════════════════════════════════════════════════
 *  STABILITY CONTRACT — v1.0.0-embedded-stable
 * ════════════════════════════════════════════════════════════════
 *
 *  The following are FROZEN and MUST NOT change:
 *
 *    1. Canonical string format:
 *       version|message_type|device_id|tenant_id|timestamp|message_id|nonce
 *
 *    2. Validation pipeline order (7 steps):
 *       Version → Timestamp → PayloadSize → Nonce → PayloadHash → Sequence → Signature
 *
 *    3. Crypto interface contract:
 *       sha256(), hmac_sha256(), constant_time_equal(), constant_time_hex_equal()
 *       hex_encode(), hex_decode(), base64_encode(), generate_nonce()
 *       aes256_gcm_decrypt(), aes256_gcm_encrypt()
 *
 *    4. Binary frame format:
 *       [0-1] MAGIC "HX" | [2] VERSION=2 | [3] TYPE | [4-7] JSON_LEN BE | [8..] JSON
 *
 *    5. Error code values (match server enum)
 *
 *  Rules:
 *    - No silent behavior changes
 *    - No validation order changes
 *    - No crypto API changes
 *    - No canonical string changes
 *    - No signature downgrade
 *    - No plaintext mode
 *    - No downgrade path allowed
 *
 * ════════════════════════════════════════════════════════════════
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef HXTP_CONFIG_H
#define HXTP_CONFIG_H

/* ── SDK Version ────────────────────────────────────────────────────── */

#define HXTP_SDK_VERSION_MAJOR  1
#define HXTP_SDK_VERSION_MINOR  0
#define HXTP_SDK_VERSION_PATCH  0
#define HXTP_SDK_VERSION_TAG    "v1.0.0-embedded-stable"

/* ── Build Profile Flags ────────────────────────────────────────────── */
/*
 * Exactly ONE of these should be defined (via platformio.ini or compiler flag).
 * If none is defined, HXTP_RELEASE is assumed.
 *
 *   HXTP_RELEASE      — Production build. Full features, full validation.
 *   HXTP_DEBUG         — Development build. Enables verbose error messages,
 *                        optional Serial diagnostics. Same crypto. Same validation.
 *   HXTP_LITE          — Reduced features for memory-constrained ESP32.
 *                        Smaller nonce cache, smaller frame buffer.
 *                        Full crypto. Full validation.
 *   HXTP_CONSTRAINED   — ESP8266 Tier-3 mode. Minimal buffers, no AES-GCM at-rest,
 *                        no OTA. Full HMAC-SHA256. Full 7-step validation.
 *                        Activated automatically on ESP8266 unless overridden.
 */

/* Auto-select HXTP_CONSTRAINED for ESP8266 if no profile is explicitly set */
#if defined(ESP8266) && !defined(HXTP_RELEASE) && !defined(HXTP_DEBUG) && !defined(HXTP_LITE) && !defined(HXTP_CONSTRAINED)
    #define HXTP_CONSTRAINED 1
#endif

/* Default to HXTP_RELEASE if nothing set */
#if !defined(HXTP_RELEASE) && !defined(HXTP_DEBUG) && !defined(HXTP_LITE) && !defined(HXTP_CONSTRAINED)
    #define HXTP_RELEASE 1
#endif

/* ── Feature Gate Macros ────────────────────────────────────────────── */

/*
 * HXTP_FEATURE_AES_GCM — AES-256-GCM at-rest encryption.
 *   Enabled on ESP32 (mbedTLS). Available on ESP8266 (BearSSL) but
 *   disabled by default in HXTP_CONSTRAINED to save ~2 KB stack.
 *   Can be force-enabled: -DHXTP_FEATURE_AES_GCM=1
 */
#ifndef HXTP_FEATURE_AES_GCM
    #if defined(HXTP_CONSTRAINED)
        #define HXTP_FEATURE_AES_GCM  0
    #else
        #define HXTP_FEATURE_AES_GCM  1
    #endif
#endif

/*
 * HXTP_FEATURE_OTA — Over-the-air update support.
 *   Disabled on constrained devices. Scaffold only — not yet implemented.
 */
#ifndef HXTP_FEATURE_OTA
    #if defined(HXTP_CONSTRAINED)
        #define HXTP_FEATURE_OTA  0
    #else
        #define HXTP_FEATURE_OTA  0  /* Not yet implemented on any tier */
    #endif
#endif

/*
 * HXTP_FEATURE_DUAL_KEY — Dual-key rotation fallback on signature verify.
 *   Always enabled. Cannot be disabled — security invariant.
 */
#define HXTP_FEATURE_DUAL_KEY  1

/*
 * HXTP_FEATURE_VERBOSE_ERRORS — Include human-readable error messages.
 *   Enabled in DEBUG. Disabled in CONSTRAINED to save flash.
 */
#ifndef HXTP_FEATURE_VERBOSE_ERRORS
    #if defined(HXTP_DEBUG)
        #define HXTP_FEATURE_VERBOSE_ERRORS  1
    #elif defined(HXTP_CONSTRAINED)
        #define HXTP_FEATURE_VERBOSE_ERRORS  0
    #else
        #define HXTP_FEATURE_VERBOSE_ERRORS  1
    #endif
#endif

/* ── Tunable Sizes (override via -D flag) ───────────────────────────── */

/*
 * Nonce cache size.
 *   Default: 64 (ESP32), 16 (CONSTRAINED/ESP8266)
 *   Tradeoff: smaller cache = shorter replay protection window.
 *   Minimum safe value: 8 (protects ~80 seconds at 10 msg/s)
 */
#ifndef HXTP_NONCE_CACHE_SIZE_OVERRIDE
    #if defined(HXTP_CONSTRAINED)
        #define HXTP_NONCE_CACHE_SIZE_OVERRIDE  16
    #elif defined(HXTP_LITE)
        #define HXTP_NONCE_CACHE_SIZE_OVERRIDE  32
    #endif
    /* else: uses HXTP_NONCE_CACHE_SIZE from Types.h (64) */
#endif

/*
 * Frame buffer size default.
 *   Default: 4096 (ESP32), 1536 (CONSTRAINED)
 *   Must be >= HXTP_HEADER_SIZE + minimum JSON envelope (~200 bytes).
 */
#ifndef HXTP_FRAME_BUF_OVERRIDE
    #if defined(HXTP_CONSTRAINED)
        #define HXTP_FRAME_BUF_OVERRIDE  1536
    #elif defined(HXTP_LITE)
        #define HXTP_FRAME_BUF_OVERRIDE  2048
    #endif
    /* else: uses HXTP_FRAME_BUF_DEFAULT from Types.h (4096) */
#endif

/*
 * Maximum capabilities.
 *   Default: 32 (ESP32), 8 (CONSTRAINED)
 */
#ifndef HXTP_MAX_CAPABILITIES_OVERRIDE
    #if defined(HXTP_CONSTRAINED)
        #define HXTP_MAX_CAPABILITIES_OVERRIDE  8
    #elif defined(HXTP_LITE)
        #define HXTP_MAX_CAPABILITIES_OVERRIDE  16
    #endif
    /* else: uses HXTP_MAX_CAPABILITIES from Types.h (32) */
#endif

/* ── Security Invariants (compile-time assertions) ──────────────────── */

/*
 * These CANNOT be changed. They exist as documentation and compile guards.
 * HMAC-SHA256 is mandatory on ALL tiers including CONSTRAINED.
 * The 7-step validation pipeline runs identically on all tiers.
 * Constant-time signature comparison is mandatory on all tiers.
 */
#define HXTP_SECURITY_HMAC_SHA256_MANDATORY     1
#define HXTP_SECURITY_VALIDATION_7STEP          1
#define HXTP_SECURITY_CONSTANT_TIME_SIG_CMP     1
#define HXTP_SECURITY_NO_PLAINTEXT_MODE         1
#define HXTP_SECURITY_NO_SIGNATURE_DOWNGRADE    1

/* ── Memory Footprint Baseline (v1.0.0-embedded-stable) ─────────────── */
/*
 * ESP32-S3 (8 MB flash):  RAM 13.8% (45 KB / 320 KB)  Flash 29.6% (991 KB / 3.2 MB)
 * ESP32    (4 MB flash):  RAM 13.9% (45 KB / 320 KB)  Flash 51.7% (1016 KB / 1.9 MB*)
 * ESP8266  (4 MB flash):  RAM 39.5% (32 KB /  80 KB)  Flash 39.6% (414 KB / 1.0 MB)
 *   * ESP32 uses min_spiffs partition table
 *
 * HXTP SDK own code:  ESP32 ~11.3 KB flash  |  ESP8266 ~12.6 KB flash
 * Crypto backend:     mbedTLS ~88.5 KB       |  BearSSL ~56.1 KB
 * HXTP Crypto adapter: ESP32 ~1.3 KB         |  ESP8266 ~1.1 KB
 */

/* ── Convenience alias per stability contract ────────────────────────── */
#if defined(HXTP_CONSTRAINED) && defined(ESP8266)
    #define HXTP_ESP8266_CONSTRAINED 1
#endif

#endif /* HXTP_CONFIG_H */
