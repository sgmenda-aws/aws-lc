// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "../fipsmodule/delocate.h"
#include "../pqt/pqt_kem.h"
#include "../internal.h"
#include "../kyber/kem_kyber.h"
#include "../ml_kem/ml_kem.h"
#include "internal.h"


// The KEM parameters listed below are taken from corresponding specifications.
//
// Kyber: - https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
//        - Kyber is not standardized yet, so we use the latest specification
//          from Round 3 of NIST PQC project.

#define AWSLC_NUM_BUILT_IN_KEMS 9

// TODO(awslc): placeholder OIDs, replace with the real ones when available.
static const uint8_t kOIDKyber512r3[]   = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDKyber768r3[]   = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDKyber1024r3[]  = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDMLKEM512IPD[]  = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDMLKEM768IPD[]  = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDMLKEM1024IPD[] = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDPQT25519[]     = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDPQT256[]       = {0xff, 0xff, 0xff, 0xff};
static const uint8_t kOIDPQT384[]       = {0xff, 0xff, 0xff, 0xff};

static const KEM built_in_kems[AWSLC_NUM_BUILT_IN_KEMS] = {
  {
    NID_KYBER512_R3,                // kem.nid
    kOIDKyber512r3,                 // kem.oid
    sizeof(kOIDKyber512r3),         // kem.oid_len
    "Kyber512 Round-3",             // kem.comment
    KYBER512_R3_PUBLIC_KEY_BYTES,   // kem.public_key_len
    KYBER512_R3_SECRET_KEY_BYTES,   // kem.secret_key_len
    KYBER512_R3_CIPHERTEXT_BYTES,   // kem.ciphertext_len
    KYBER_R3_SHARED_SECRET_LEN,     // kem.shared_secret_len
    KYBER_R3_KEYGEN_SEED_LEN,       // kem.keygen_seed_len
    KYBER_R3_ENCAPS_SEED_LEN,       // kem.encaps_seed_len
    &kem_kyber512r3_method,         // kem.method
  },

  {
    NID_KYBER768_R3,                // kem.nid
    kOIDKyber768r3,                 // kem.oid
    sizeof(kOIDKyber768r3),         // kem.oid_len
    "Kyber768 Round-3",             // kem.comment
    KYBER768_R3_PUBLIC_KEY_BYTES,   // kem.public_key_len
    KYBER768_R3_SECRET_KEY_BYTES,   // kem.secret_key_len
    KYBER768_R3_CIPHERTEXT_BYTES,   // kem.ciphertext_len
    KYBER_R3_SHARED_SECRET_LEN,     // kem.shared_secret_len
    KYBER_R3_KEYGEN_SEED_LEN,       // kem.keygen_seed_len
    KYBER_R3_ENCAPS_SEED_LEN,       // kem.encaps_seed_len
    &kem_kyber768r3_method,         // kem.method
  },

  {
    NID_KYBER1024_R3,               // kem.nid
    kOIDKyber1024r3,                // kem.oid
    sizeof(kOIDKyber1024r3),        // kem.oid_len
    "Kyber1024 Round-3",            // kem.comment
    KYBER1024_R3_PUBLIC_KEY_BYTES,  // kem.public_key_len
    KYBER1024_R3_SECRET_KEY_BYTES,  // kem.secret_key_len
    KYBER1024_R3_CIPHERTEXT_BYTES,  // kem.ciphertext_len
    KYBER_R3_SHARED_SECRET_LEN,     // kem.shared_secret_len
    KYBER_R3_KEYGEN_SEED_LEN,       // kem.keygen_seed_len
    KYBER_R3_ENCAPS_SEED_LEN,       // kem.encaps_seed_len
    &kem_kyber1024r3_method,        // kem.method
  },
  {
    NID_MLKEM512IPD,                // kem.nid
    kOIDMLKEM512IPD,                // kem.oid
    sizeof(kOIDMLKEM512IPD),        // kem.oid_len
    "MLKEM512 IPD",                 // kem.comment
    MLKEM512IPD_PUBLIC_KEY_BYTES,   // kem.public_key_len
    MLKEM512IPD_SECRET_KEY_BYTES,   // kem.secret_key_len
    MLKEM512IPD_CIPHERTEXT_BYTES,   // kem.ciphertext_len
    MLKEM512IPD_SHARED_SECRET_LEN,  // kem.shared_secret_len
    MLKEM512IPD_KEYGEN_SEED_LEN,    // kem.keygen_seed_len
    MLKEM512IPD_ENCAPS_SEED_LEN,    // kem.encaps_seed_len
    &kem_ml_kem_512_ipd_method,     // kem.method
  },
  {
    NID_MLKEM768IPD,                // kem.nid
    kOIDMLKEM768IPD,                // kem.oid
    sizeof(kOIDMLKEM768IPD),        // kem.oid_len
    "MLKEM768 IPD",                 // kem.comment
    MLKEM768IPD_PUBLIC_KEY_BYTES,   // kem.public_key_len
    MLKEM768IPD_SECRET_KEY_BYTES,   // kem.secret_key_len
    MLKEM768IPD_CIPHERTEXT_BYTES,   // kem.ciphertext_len
    MLKEM768IPD_SHARED_SECRET_LEN,  // kem.shared_secret_len
    MLKEM768IPD_KEYGEN_SEED_LEN,    // kem.keygen_seed_len
    MLKEM768IPD_ENCAPS_SEED_LEN,    // kem.encaps_seed_len
    &kem_ml_kem_768_ipd_method,     // kem.method
  },
  {
    NID_MLKEM1024IPD,               // kem.nid
    kOIDMLKEM1024IPD,               // kem.oid
    sizeof(kOIDMLKEM1024IPD),       // kem.oid_len
    "MLKEM1024 IPD",                // kem.comment
    MLKEM1024IPD_PUBLIC_KEY_BYTES,  // kem.public_key_len
    MLKEM1024IPD_SECRET_KEY_BYTES,  // kem.secret_key_len
    MLKEM1024IPD_CIPHERTEXT_BYTES,  // kem.ciphertext_len
    MLKEM1024IPD_SHARED_SECRET_LEN, // kem.shared_secret_len
    MLKEM1024IPD_KEYGEN_SEED_LEN,   // kem.keygen_seed_len
    MLKEM1024IPD_ENCAPS_SEED_LEN,   // kem.encaps_seed_len
    &kem_ml_kem_1024_ipd_method,    // kem.method
  },
  {
    NID_PQT25519,                   // kem.nid
    kOIDPQT25519,                   // kem.oid
    sizeof(kOIDPQT25519),           // kem.oid_len
    "PQT25519",                     // kem.comment
    PQT25519_PUBLIC_KEY_BYTES,      // kem.public_key_len
    PQT25519_SECRET_KEY_BYTES,      // kem.secret_key_len
    PQT25519_CIPHERTEXT_BYTES,      // kem.ciphertext_len
    PQT25519_SHARED_SECRET_LEN,     // kem.shared_secret_len
    PQT25519_KEYGEN_SEED_LEN,       // kem.keygen_seed_len
    PQT25519_ENCAPS_SEED_LEN,       // kem.encaps_seed_len
    &kem_pqt25519_method,           // kem.method
  },
  {
    NID_PQT256,                     // kem.nid
    kOIDPQT256,                     // kem.oid
    sizeof(kOIDPQT256),             // kem.oid_len
    "PQT256",                       // kem.comment
    PQT256_PUBLIC_KEY_BYTES,        // kem.public_key_len
    PQT256_SECRET_KEY_BYTES,        // kem.secret_key_len
    PQT256_CIPHERTEXT_BYTES,        // kem.ciphertext_len
    PQT256_SHARED_SECRET_LEN,       // kem.shared_secret_len
    PQT256_KEYGEN_SEED_LEN,         // kem.keygen_seed_len
    PQT256_ENCAPS_SEED_LEN,         // kem.encaps_seed_len
    &kem_pqt256_method,             // kem.method
  },
  {
    NID_PQT384,                     // kem.nid
    kOIDPQT384,                     // kem.oid
    sizeof(kOIDPQT384),             // kem.oid_len
    "PQT384",                       // kem.comment
    PQT384_PUBLIC_KEY_BYTES,        // kem.public_key_len
    PQT384_SECRET_KEY_BYTES,        // kem.secret_key_len
    PQT384_CIPHERTEXT_BYTES,        // kem.ciphertext_len
    PQT384_SHARED_SECRET_LEN,       // kem.shared_secret_len
    PQT384_KEYGEN_SEED_LEN,         // kem.keygen_seed_len
    PQT384_ENCAPS_SEED_LEN,         // kem.encaps_seed_len
    &kem_pqt384_method,             // kem.method
  },
};

const KEM *KEM_find_kem_by_nid(int nid) {
  const KEM *ret = NULL;
  for (size_t i = 0; i < AWSLC_NUM_BUILT_IN_KEMS; i++) {
    if (built_in_kems[i].nid == nid) {
      ret = &built_in_kems[i];
      break;
    }
  }
  return ret;
}

KEM_KEY *KEM_KEY_new(void) {
  KEM_KEY *ret = OPENSSL_zalloc(sizeof(KEM_KEY));
  if (ret == NULL) {
    return NULL;
  }

  return ret;
}

static void KEM_KEY_clear(KEM_KEY *key) {
  key->kem = NULL;
  OPENSSL_free(key->public_key);
  OPENSSL_free(key->secret_key);
  key->public_key = NULL;
  key->secret_key = NULL;
}

int KEM_KEY_init(KEM_KEY *key, const KEM *kem) {
  if (key == NULL || kem == NULL) {
    return 0;
  }
  // If the key is already initialized clear it.
  KEM_KEY_clear(key);

  key->kem = kem;
  key->public_key = OPENSSL_malloc(kem->public_key_len);
  key->secret_key = OPENSSL_malloc(kem->secret_key_len);
  if (key->public_key == NULL || key->secret_key == NULL) {
    KEM_KEY_clear(key);
    return 0;
  }

  return 1;
}

void KEM_KEY_free(KEM_KEY *key) {
  if (key == NULL) {
    return;
  }
  KEM_KEY_clear(key);
  OPENSSL_free(key);
}

const KEM *KEM_KEY_get0_kem(KEM_KEY* key) {
  return key->kem;
}

int KEM_KEY_set_raw_public_key(KEM_KEY *key, const uint8_t *in) {
  key->public_key = OPENSSL_memdup(in, key->kem->public_key_len);
  if (key->public_key == NULL) {
    return 0;
  }

  return 1;
}

int KEM_KEY_set_raw_secret_key(KEM_KEY *key, const uint8_t *in) {
  key->secret_key = OPENSSL_memdup(in, key->kem->secret_key_len);
  if (key->secret_key == NULL) {
    return 0;
  }

  return 1;
}

int KEM_KEY_set_raw_key(KEM_KEY *key, const uint8_t *in_public,
                                      const uint8_t *in_secret) {
  key->public_key = OPENSSL_memdup(in_public, key->kem->public_key_len);
  key->secret_key = OPENSSL_memdup(in_secret, key->kem->secret_key_len);
  if (key->public_key == NULL || key->secret_key == NULL) {
    KEM_KEY_clear(key);
    return 0;
  }

  return 1;
}
