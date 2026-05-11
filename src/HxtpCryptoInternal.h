/*
 * HxtpCryptoInternal.h
 * Wrapper for Monocypher (Ed25519)
 */

#ifndef HXTP_CRYPTO_INTERNAL_H
#define HXTP_CRYPTO_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ed25519 wrapper */
int hxtp_crypto_sign_keypair(uint8_t *pk, uint8_t *sk, bool (*rng)(uint8_t*, size_t));
int hxtp_crypto_sign_detached(uint8_t *sig, const uint8_t *m, size_t n, const uint8_t *sk, const uint8_t *pk);
int hxtp_crypto_sign_verify(const uint8_t *sig, const uint8_t *m, size_t n, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif /* HXTP_CRYPTO_INTERNAL_H */
