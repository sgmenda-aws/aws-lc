# Hybrid Post-Quantum KEMs

The source code in this folder implements hybrid post-quantum KEMs as defined in (LINK TO DRAFT).

NOTE: THIS IS AN IMPLEMENTATION OF A DRAFT, NOT A FINAL STANDARD.

## Parameter Sets

We implement three parameter sets:

1. `hpqkem25519`: hybrid of `mlkem768` and `x25519` with `hkdf-sha2-256`.
2. `hpqkem256`: hybrid of `mlkem768` and `p256` with `hkdf-sha2-256`.
3. `hpqkem384`: hybrid of `mlkem1024` and `p384` with `hkdf-sha2-384`.

TODO(sanketh): the choice of KEMs is fixed but the choice of hash and what to hash is still under construction.

TODO(sanketh): compare different hash functions and different amount of information to be hashed.

## Usage

These KEMs implement the standard KEM API, see [crypto/kem/README.md](../kem/README.md).

## Architecture

TODO(sanketh): describe the architecture.

## KATs and Testing

There are no KATs at the moment, since this design is not stable yet.

TODO(sanketh): add non-KATs tests.

## Notes

The internal implementation of DHKEM does not match [RFC 9180 §4.1](https://www.rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem). This is intentional to avoid an unnecessary hash invocation since the hybrid KEM hashes the public key and ciphertext.
