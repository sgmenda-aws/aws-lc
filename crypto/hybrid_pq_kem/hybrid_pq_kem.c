// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "hybrid_pq_kem.h"

#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include "../internal.h"

#define HPQKEM_LABEL "hpqkem"
#define HPQKEM_LABEL_LEN 7

int hpqkem25519_keygen_deterministic(uint8_t *public_key, uint8_t *secret_key,
                                     const uint8_t *seed) {
  // Use first 2*SYMBYTES of seed to generate an ML-KEM keypair
  // NOTE: this function (imported from kyber upstream) returns 0 on success
  if (ml_kem_768_ipd_keypair_deterministic(public_key, secret_key, seed) != 0) {
    return 0;
  }

  uint8_t *x25519_public_key = public_key + MLKEM768IPD_PUBLIC_KEY_BYTES;
  uint8_t *x25519_secret_key = secret_key + MLKEM768IPD_SECRET_KEY_BYTES;

  // Use the remaining SYMBYTES as the X25519 secret key
  OPENSSL_memcpy(x25519_secret_key, seed + 2 * HPQKEM_SYMBYTES,
                 HPQKEM_SYMBYTES);
  X25519_public_from_private(x25519_public_key, x25519_secret_key);

  // Append the public key at the end of the secret key, for easy access
  OPENSSL_memcpy(
      secret_key + MLKEM768IPD_SECRET_KEY_BYTES + X25519_PRIVATE_KEY_LEN,
      public_key, HPQKEM25519_PUBLIC_KEY_BYTES);

  return 1;
}

int hpqkem25519_keygen(uint8_t *public_key, uint8_t *secret_key) {
  uint8_t seed[HPQKEM_KEYGEN_SEED_LEN];
  RAND_bytes(seed, HPQKEM_KEYGEN_SEED_LEN);
  return hpqkem25519_keygen_deterministic(public_key, secret_key, seed);
}

// Computes HKDF(key = combined_ss, salt = salt, label = [hardcoded])
// Returns 1 on success and 0 otherwise.
static inline int hpqkem_generate_shared_secret(
    uint8_t shared_secret[HPQKEM_SHARED_SECRET_LEN], const EVP_MD *digest,
    const uint8_t combined_shared_secrets[2 * HPQKEM_SHARED_SECRET_LEN],
    const uint8_t *salt, size_t salt_len) {
  uint8_t info[HPQKEM_LABEL_LEN] = HPQKEM_LABEL;
  size_t info_len = HPQKEM_LABEL_LEN;

  return HKDF(shared_secret, HPQKEM_SHARED_SECRET_LEN, digest,
              combined_shared_secrets, 2 * HPQKEM_SHARED_SECRET_LEN, salt,
              salt_len, info, info_len);
}

// Computes HKDF(key = ss1 || ss2, salt = pk1 || pk2 || ct1 || ct2)
// Returns 1 on success and 0 otherwise.
static inline int hpqkem25519_generate_shared_secret(
    uint8_t shared_secret[HPQKEM_SHARED_SECRET_LEN],
    const uint8_t combined_shared_secrets[2 * HPQKEM_SHARED_SECRET_LEN],
    const uint8_t ciphertext[HPQKEM25519_CIPHERTEXT_BYTES],
    const uint8_t public_key[HPQKEM25519_PUBLIC_KEY_BYTES]) {
  // Constants
  const EVP_MD *digest = EVP_sha256();

  uint8_t salt[HPQKEM25519_PUBLIC_KEY_BYTES + HPQKEM25519_CIPHERTEXT_BYTES];
  size_t salt_len = HPQKEM25519_PUBLIC_KEY_BYTES + HPQKEM25519_CIPHERTEXT_BYTES;
  OPENSSL_memcpy(salt, public_key, HPQKEM25519_PUBLIC_KEY_BYTES);
  OPENSSL_memcpy(salt + HPQKEM25519_PUBLIC_KEY_BYTES, ciphertext,
                 HPQKEM25519_CIPHERTEXT_BYTES);

  return hpqkem_generate_shared_secret(shared_secret, digest,
                                       combined_shared_secrets, salt, salt_len);
}

int hpqkem25519_encaps_deterministic(uint8_t *ciphertext,
                                     uint8_t *shared_secret,
                                     const uint8_t *public_key,
                                     const uint8_t *seed) {
  // Partition buffers
  uint8_t *mlkem_ciphertext = ciphertext;
  uint8_t *x25519_ciphertext = ciphertext + MLKEM768IPD_CIPHERTEXT_BYTES;
  const uint8_t *mlkem_public_key = public_key;
  const uint8_t *x25519_public_key = public_key + MLKEM768IPD_PUBLIC_KEY_BYTES;
  const uint8_t *mlkem_seed = seed;
  const uint8_t *x25519_seed = seed + HPQKEM_SYMBYTES;

  // Create buffer to hold combined shared secrets
  uint8_t combined_shared_secrets[2 * HPQKEM_SHARED_SECRET_LEN] = {};
  uint8_t *mlkem_shared_secret = combined_shared_secrets;
  uint8_t *x25519_shared_secret =
      combined_shared_secrets + MLKEM768IPD_SHARED_SECRET_LEN;

  // ML-KEM encapsulate
  // NOTE: this function (imported from kyber upstream) returns 0 on success
  if (ml_kem_768_ipd_encapsulate_deterministic(
          mlkem_ciphertext, mlkem_shared_secret, mlkem_public_key,
          mlkem_seed) != 0) {
    return 0;
  }

  // X25519 encapsulate
  // Interpret seed as ephemeral private key
  const uint8_t *x25519_ephemeral_private_key = x25519_seed;
  // The corresponding public key is the ciphertext
  X25519_public_from_private(x25519_ciphertext, x25519_ephemeral_private_key);
  // Do key exchange with the peer's public key to generate a shared secret
  if (X25519(x25519_shared_secret, x25519_ephemeral_private_key,
             x25519_public_key) != 1) {
    return 0;
  }

  return hpqkem25519_generate_shared_secret(
      shared_secret, combined_shared_secrets, ciphertext, public_key);
}

int hpqkem25519_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                       const uint8_t *public_key) {
  uint8_t seed[HPQKEM_ENCAPS_SEED_LEN];
  RAND_bytes(seed, HPQKEM_ENCAPS_SEED_LEN);
  return hpqkem25519_encaps_deterministic(ciphertext, shared_secret, public_key,
                                          seed);
}

int hpqkem25519_decaps(uint8_t *shared_secret, const uint8_t *ciphertext,
                       const uint8_t *secret_key) {
  // Partition buffers
  const uint8_t *mlkem_ciphertext = ciphertext;
  const uint8_t *x25519_ciphertext = ciphertext + MLKEM768IPD_CIPHERTEXT_BYTES;
  const uint8_t *mlkem_secret_key = secret_key;
  const uint8_t *x25519_secret_key = secret_key + MLKEM768IPD_SECRET_KEY_BYTES;

  // Recover public key
  const uint8_t *public_key =
      secret_key + MLKEM768IPD_SECRET_KEY_BYTES + X25519_PRIVATE_KEY_LEN;

  // Create buffer to hold combined shared secrets
  uint8_t combined_shared_secrets[2 * HPQKEM_SHARED_SECRET_LEN] = {};
  uint8_t *mlkem_shared_secret = combined_shared_secrets;
  uint8_t *x25519_shared_secret =
      combined_shared_secrets + MLKEM768IPD_SHARED_SECRET_LEN;

  // ML-KEM decapsulate
  // NOTE: this function (imported from kyber upstream) returns 0 on success
  if (ml_kem_768_ipd_decapsulate(mlkem_shared_secret, mlkem_ciphertext,
                                 mlkem_secret_key) != 0) {
    return 0;
  }

  // X25519 decapsulate
  // Do key exchange with secret key to recover shared secret
  if (X25519(x25519_shared_secret, x25519_secret_key, x25519_ciphertext) != 1) {
    return 0;
  }

  return hpqkem25519_generate_shared_secret(
      shared_secret, combined_shared_secrets, ciphertext, public_key);
}
