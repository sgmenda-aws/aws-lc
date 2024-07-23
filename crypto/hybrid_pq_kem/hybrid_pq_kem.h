// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#ifndef HYBRID_PQ_KEM_H
#define HYBRID_PQ_KEM_H

#include <stdint.h>

#include <openssl/curve25519.h>

#include "../ml_kem/ml_kem.h"

// Length of the generated shared secret.
#define HPQKEM_SHARED_SECRET_LEN 32
// Length of internal seeds.
#define HPQKEM_SYMBYTES 32
// ML-KEM needs 2*SYMBYTES: SYMBYTES for keys and SYMBYTES for rejection value
// z. ECC needs SYMBYTES for keys. For a total of 3*SYMBYTES.
#define HPQKEM_KEYGEN_SEED_LEN (3 * HPQKEM_SYMBYTES)
// ML-KEM and ECC each need SYMBYTES for encaps.
#define HPQKEM_ENCAPS_SEED_LEN (2 * HPQKEM_SYMBYTES)

#define HPQKEM25519_PUBLIC_KEY_BYTES \
  (MLKEM768IPD_PUBLIC_KEY_BYTES + X25519_PUBLIC_VALUE_LEN)
#define HPQKEM25519_SECRET_KEY_BYTES                       \
  (MLKEM768IPD_SECRET_KEY_BYTES + X25519_PRIVATE_KEY_LEN + \
   HPQKEM25519_PUBLIC_KEY_BYTES)
#define HPQKEM25519_CIPHERTEXT_BYTES \
  (MLKEM768IPD_CIPHERTEXT_BYTES + X25519_PUBLIC_VALUE_LEN)

// Generates keys and writes them to |public_key| and |secret_key|.
// It returns one on success or zero on error.
int hpqkem25519_keygen(uint8_t *public_key /* OUT */,
                       uint8_t *secret_key /* OUT */);

// Encapsulates to |public_key| and writes to |shared_secret| and |ciphertext|.
// It returns one on success or zero on error.
int hpqkem25519_encaps(uint8_t *ciphertext /* OUT */,
                       uint8_t *shared_secret /* OUT */,
                       const uint8_t *public_key /* IN  */);

// Decapsulates |ciphertext| to |secret_key| and writes to |shared_secret|.
// It returns one on success or zero on error.
int hpqkem25519_decaps(uint8_t *shared_secret /* OUT */,
                       const uint8_t *ciphertext /* IN  */,
                       const uint8_t *secret_key /* IN  */);

// Deterministic variant of |hpqkem25519_keygen|.
// It returns one on success or zero on error.
int hpqkem25519_keygen_deterministic(uint8_t *public_key /* OUT */,
                                     uint8_t *secret_key /* OUT */,
                                     const uint8_t *seed /* IN */);

// Deterministic variant of |hpqkem25519_encaps|.
// It returns one on success or zero on error.
int hpqkem25519_encaps_deterministic(uint8_t *ciphertext /* OUT */,
                                     uint8_t *shared_secret /* OUT */,
                                     const uint8_t *public_key /* IN  */,
                                     const uint8_t *seed /* IN */);

#endif  // HYBRID_PQ_KEM_H
