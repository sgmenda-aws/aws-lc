# Design of PQ/T Hybrid KEMs

NOTE: THIS IS AN EARLY DRAFT.

## Introduction

We implement three concrete hybrid PQ/T KEMs, inspired by [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

1. `pqt25519`: hybrid of `mlkem768` and `x25519` with `hkdf-sha2-256`.
2. `pqt256`: hybrid of `mlkem768` and `p256` with `hkdf-sha2-256`.
3. `pqt384`: hybrid of `mlkem1024` and `p384` with `hkdf-sha2-384`.

**Security.** All KEMs provide IND-CCA, LEAK-BIND-K-CT, and LEAK-BIND-K-PK security.

**Choice of KDF.** All KEMs use HKDF-SHA2 because it is ubiqitous.

FIXME(sanketh): Reconsider choice of KDF.

**Authentication.** These KEMs are not authenticated KEMs. While they can be modified to provide classical authentication, similar to DHKEM. We explicitly choose not to instantiate them that way because the resulting authenticated KEMs would be vulnerable to _key impersonation attacks_; that is, an attacker with knowledge of the recipient secret key can generate a valid ciphertext impersonating a sender, without compromising the sender's secret key, see Section 5.4 of [Alwen et al. (2020)](https://eprint.iacr.org/2020/1499).

#### [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)

`pqt25519` is X-Wing, except it uses `hkdf-sha2-256` instead of raw `sha3-256`.

`pqt256` and `pqt384` are extensions of X-Wing to support NIST-P curves, they can be seen as an evolution of X-Wing and the DHKEM construction in [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/).

#### [ETSI TS 103 744](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=56901)

`pqt*` do not hash the ML-KEM ciphertext or public key.

#### [Xyber768](https://datatracker.ietf.org/doc/draft-westerbaan-cfrg-hpke-xyber768d00/)

`pqt*` use the raw DH groups (instead of DHKEM) and do not hash the ML-KEM ciphertext.

#### [cfrg-kem-combiners](https://datatracker.ietf.org/doc/draft-ounsworth-cfrg-kem-combiners/)

`pqt*` use the raw DH groups (instead of DHKEM) and do not hash the ML-KEM ciphertext.

<!-- # Requirements Notation -->

## Notation

1. All variables are bytes.
2. `concat(bytes, bytes,...) -> bytes`: concatention of bytes
3. `A[n]`: `n`th byte in `A`, under 0-indexing
4. `A[..n]`: `{A[0],...,A[n-1]}`
5. `A[n..]`: `{A[n],...}`

## Cryptographic Dependencies

We rely on the following primitives:

1. ML-KEM-768 and ML-KEM-1024 KEMs [FIPS 203 IPD]:
1. `ML-KEM-*.KeyGenDeterministic(seed) -> (public_key, secret_key)`
1. `ML-KEM-*.EncapsDeterministic(public_key, seed) -> (ciphertext, shared_secret)`
1. `ML-KEM-*.Decaps(ciphertext, secret_key) -> shared_secret`
1. X25519, P-256, and P-384 serialization functions [RFC 9180, Section 7.1]:
1. `*.SerializePublicKey(*_public_key) -> bytes`
1. `*.DeserializePublicKey(bytes) -> *_public_key`
1. `*.SerializePrivateKey(*_secret_key) -> bytes`
1. `*.DeserializePrivateKey(bytes) -> *_secret_key`
1. HKDF-SHA256 and HKDF-SHA384 [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869):
1. `HKDF-*(key, salt, info) -> bytes`
1. X25519 ephemeral-ephemeral key exchange [RFC 7748]:
1. `X25519.KeyGenDeterministic(seed) -> (public_key, secret_key)`
1. `X25519.DH(public_key, secret_key) -> shared_secret`
1. P-256 and P-384 ephemeral-ephemeral key exchange [NIST.SP.800-56Ar3]:
1. `*.KeyGenDeterministic(seed) -> (public_key, secret_key)`
1. `*.DH(public_key, secret_key) -> shared_secret`

## Construction

### API Notes

**Randomness.** All functions are deterministic. They can be turned into randomized functions in the standard way by wrapping with a function that generates the random bytes.

**Decapsulation failures.** ML-KEM is an _implicitly rejecting_ KEM, meaning that Decaps always produces a value, but in the case of decapsulation failure, the produced value is random garbage. The proposed KEMs fallthrough this behavior, and therefore are also implicitly rejecting.

### Structures

All inputs and outputs are fixed-length byte strings.

| KEM      | Shared Secret | Public Key | Secret Key     | Ciphertext | Keygen Seed | Encaps Seed |
| :------- | :------------ | :--------- | -------------- | ---------- | ----------- | ----------- |
| PQT25519 | 32            | 1184 + 32  | 2400 + 32 + 32 | 1088 + 32  | 64 + 32     | 32 + 32     |
| PQT256   | 32            | 1184 + 65  | 2400 + 32 + 65 | 1088 + 65  | 64 + ??     | 32 + ??     |
| PQT384   | 32            | 1568 + 97  | 3168 + 48 + 97 | 1568 + 97  | 64 + ??     | 32 + ??     |

**Shared secrets.** All shared secrets are 32 byte strings.

**Public keys.** Public keys are concatenations of the PQ public key and the T public key.

**Secret keys.** Secret keys are concatentations of the PQ secret key, the T secret key, and the T public key. (We do not need to include the ML-KEM public key because the ML-KEM secret key includes it.)

**Ciphertexts.** Ciphertexts are concatentations of the PQ ciphertext and the T ciphertext.

**Keygen and encaps seeds.** Keygen and encaps seeds are concatentations of the respective PQ and T values.

### Internal Constants

| KEM    | Shared Secret | Public Key | Secret Key | Ciphertext | Keygen Seed | Encaps Seed |
| :----- | :------------ | :--------- | ---------- | ---------- | ----------- | ----------- |
| PQ768  | 32            | 1184       | 2400       | 1088       | 64          | 32          |
| PQ1024 | 32            | 1568       | 3168       | 1568       | 64          | 32          |
| X25519 | 32            | 32         | 32         | 32         | 32          | 32          |
| T256   | 32            | 65         | 32         | 65         | ??          | ??          |
| T384   | 48            | 97         | 48         | 97         | ??          | ??          |

### Combiner

The `CONSTANT` is "PQT255-v1", "PQT256-v1", or "PQT384-v1", respectively.

```
def Combiner(pq_shared_secret, t_shared_secret, t_ciphertext, t_public_key):
   return HKDF-*(
      key = concat(t_shared_secret, pq_shared_secret),
      salt = concat(t_ciphertext, t_public_key),
      label = CONSTANT
   )
```

### Key Generation

```
def KeyGenDeterministic<PQ, T>(seed) -> (pqt_public_key, pqt_secret_key):
   (pq_public_key, pq_secret_key) = PQ.KeygenDeterministic(seed[..PQ_KEYGEN_SEED_LEN])
   (t_public_key, t_secret_key) = T.KeygenDeterministic(seed[PQ_KEYGEN_SEED_LEN..])
   public_key = concat(pq_public_key, t_public_key)
   secret_key = concat(pq_secret_key, t_secret_key, public_key)
   return (public_key, secret_key)
```

### Encapsulation

```
def EncapsDeterministic<PQ, T>(public_key, seed) -> (ciphertext, shared_secret):
   pq_public_key = public_key[..PQ_PUBLIC_KEY_LEN]
   t_public_key = public_key[PQ_PUBLIC_KEY_LEN..]
   (pq_ciphertext, pq_shared_secret) = PQ.EncapsDeterministic(pq_public_key, seed[..PQ_ENCAPS_SEED_LEN])
   (t_ephemeral_public_key, t_ephemeral_secret_key) = T.KeygenDeterministic(seed[PQ_ENCAPS_SEED_LEN..])
   t_ciphertext = t_ephemeral_public_key
   t_shared_secret = T.DH(t_public_key, t_ephemeral_shared_secret)
   ciphertext = concat(pq_ciphertext, t_ciphertext)
   shared_secret = Combiner(pq_shared_secret, t_shared_secret, t_ciphertext, t_public_key)
   return (ciphertext, shared_secret)
```

### Decapsulation

```
def Decaps<PQ, T>(ciphertext, secret_key) -> shared_secret:
   pq_ciphertext = ciphertext[..PQ_CIPHERTEXT_LEN]
   t_ciphertext = ciphertext[PQ_CIPHERTEXT_LEN..]
   pq_secret_key = secret_key[..PQ_SECRET_KEY_LEN]
   t_secret_key = secret_key[PQ_SECRET_KEY_LEN..(PQ_SECRET_KEY_LEN + T_SECRET_KEY_LEN)]
   t_public_key = secret_key[(PQ_SECRET_KEY_LEN + T_SECRET_KEY_LEN + PQ_PUBLIC_KEY_LEN)...]
   pq_shared_secret = PQ.Decaps(pq_ciphertext, pq_secret_key)
   t_shared_secret = T.DH(t_ciphertext, t_secret_key)
   shared_secret = Combiner(pq_shared_secret, t_shared_secret, t_ciphertext, t_public_key)
   return shared_secret
```

## Security Considerations

The proposed PQ/T hybrid KEMs are secure if HKDF-SHA256 and HKDF-SHA384 are random oracles, and either:

1. ML-KEM-768 and ML-KEM-1024 are IND-CCA KEMs; or
2. the Gap Diffie-Hellman assumption holds in Curve25519, P-256, and P-384.

And security here is IND-CCA, LEAK-BIND-K-PK, and LEAK-BIND-K-CT.

### Post-Quantum IND-CCA Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are random oracles.[^dualPRF]
2. ML-KEM-768 and ML-KEM-1024 are IND-CCA KEMs.[^C2PRI]

#### Proof

FIXME(sanketh): Write this proof, with precise bounds.

This follows from Theorem 1 of [Petcher and Campagna (2023)](https://eprint.iacr.org/2023/972) which shows that when
the shared secret is derived from a random oracle that takes the shared secrets, public keys, and ciphertexts as inputs,
the resulting KEM is IND-CCA secure if one of the internal KEMs is OW-CCA secure.

**Aside.** This also follows from Theorem 1 of [Giacon et al. (2018)](https://eprint.iacr.org/2018/024) which shows the
same result except when one of the internal KEMs is IND-CCA instead of OW-CCA, which also holds for ML-KEM-768 and
ML-KEM-1024.

### Pre-Quantum Fallback IND-CCA Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are random oracles.[^dualPRF]
2. P-256, P-384, and Curve25519 are _rerandomisable nominal groups_ where the _Gap Diffie-Hellman_ assumption holds, see
   Sections 4.1 and 4.2 of [Alwen et al. (2020)](https://eprint.iacr.org/2020/1499).

[^dualPRF]:
    With careful analysis, we can likely weaken this assumption to something like
    a [dualPRF](https://eprint.iacr.org/2023/861). See, for reference,
    the [analysis of PQ3](https://eprint.iacr.org/2024/357).

[^C2PRI]:
    Additional assumptions on the PQ KEM, specifically that it follows the FO paradigm, could enable performance
    improvements. See Section 7.2 of [Barbosa et al. (2024)](https://eprint.iacr.org/2024/039).

#### Proof

FIXME(sanketh): Write this proof, with precise bounds.

Theorem 1 in [Barbosa et al. (2024)](https://eprint.iacr.org/2024/039) proves this for `pqt25519`/X-Wing.

This proof is very similar to Theorem 7 in [Alwen et al. (2020)](https://eprint.iacr.org/2020/1499)) and Theorem 1
in [Barbosa et al. (2024)](https://eprint.iacr.org/2024/039). The high-level idea is to use the fact that the shared
secret is the output of a random oracle with the DH shared secret, DH public key, and DH ephemeral public key to force
the adversary to break the random oracle or to break the DH assumption. And we do this by a series of game hops,
constraining the adversary at each hop at the cost of some advantange.

### LEAK-BIND-K-PK and LEAK-BIND-K-CT Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are random oracles.[^dualPRF]

#### Proof

FIXME(sanketh): Write this proof, with precise bounds.

This follows from Theorems D.1 and D.2 of [Cremers et al. (2023)](https://eprint.iacr.org/2023/1933) which show that if
the shared secret is derived from a random oracle that takes the shared secrets, public keys, and ciphertexts as inputs,
the resulting KEM is LEAK-BIND-K-PK and LEAK-BIND-K-CT.
