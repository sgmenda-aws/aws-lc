# Design of PQ/T Hybrid KEMs

NOTE: THIS IS AN EARLY DRAFT.

## Introduction

We implement three concrete hybrid PQ/T KEMs, inspired by [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) and [DHKEM](https://datatracker.ietf.org/doc/rfc9180).

1. `pqt25519`: hybrid of `mlkem768` and `x25519` with `hkdf-sha2-256`.
2. `pqt256`: hybrid of `mlkem768` and `p256` with `hkdf-sha2-256`.
3. `pqt384`: hybrid of `mlkem1024` and `p384` with `hkdf-sha2-384`.

**Security.** All KEMs provide IND-CCA, LEAK-BIND-K-CT, and LEAK-BIND-K-PK security.

**Choice of KDF.** All KEMs use HKDF-SHA2 because it is ubiqitous.

FIXME(sanketh): Reconsider choice of KDF.

**Authentication.** These KEMs are not authenticated KEMs. See [Authentication](#authentication).

#### [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)

`pqt25519` is X-Wing, except it uses `hkdf-sha2-256` instead of raw `sha3-256`.

`pqt256` and `pqt384` are extensions of X-Wing to support NIST-P curves, they can be seen as an evolution of X-Wing and the DHKEM construction in [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/).

#### [ETSI TS 103 744](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=56901)

`pqt*` do not hash the ML-KEM ciphertext or public key.

#### [DHKEM](https://datatracker.ietf.org/doc/rfc9180)

`pqt*` use a simpler HKDF encoding, and perform a concurrent post-quantum key exchange.

#### [Xyber768](https://datatracker.ietf.org/doc/draft-westerbaan-cfrg-hpke-xyber768d00/)

`pqt*` use the raw DH groups (instead of DHKEM) and do not hash the ML-KEM ciphertext.

#### [cfrg-kem-combiners](https://datatracker.ietf.org/doc/draft-ounsworth-cfrg-kem-combiners/)

`pqt*` use the raw DH groups (instead of DHKEM) and do not hash the ML-KEM ciphertext.

<!-- # Requirements Notation -->

## Notation

FIXME(sanketh): Use the same notation as FIPS 203: encapsulation key, decapsulation key, etc.

1. All variables are bytes.
2. `concat(bytes, bytes,...) -> bytes`: concatention of bytes
3. `A[n]`: `n`th byte in `A`, under 0-indexing
4. `A[..n]`: `{A[0],...,A[n-1]}`
5. `A[n..]`: `{A[n],...}`

## Cryptographic Dependencies

We rely on the following primitives:

1. ML-KEM-768 and ML-KEM-1024 KEMs [FIPS 203 IPD]:
   1. `ML-KEM-*.KeyGenDeterministic(seed) -> (public_key, secret_key)`
   2. `ML-KEM-*.EncapsDeterministic(public_key, seed) -> (ciphertext, shared_secret)`
   3. `ML-KEM-*.Decaps(ciphertext, secret_key) -> shared_secret`
2. X25519, P-256, and P-384 serialization functions [RFC 9180, Section 7.1]:
   1. `*.SerializePublicKey(*_public_key) -> bytes`
   2. `*.DeserializePublicKey(bytes) -> *_public_key`
   3. `*.SerializeSecretKey(*_secret_key) -> bytes`
   4. `*.DeserializeSecretKey(bytes) -> *_secret_key`
3. HKDF-SHA256 and HKDF-SHA384 [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869):
   1. `HKDF-*(key, salt, info) -> bytes`
4. X25519 ephemeral-ephemeral key exchange [RFC 7748]:
   1. `X25519.KeyGenDeterministic(seed) -> (public_key, secret_key)`
   2. `X25519.DH(public_key, secret_key) -> shared_secret`
5. P-256 and P-384 ephemeral-ephemeral key exchange [NIST.SP.800-56Ar3]:
   1. `*.KeyGenDeterministic(seed) -> (public_key, secret_key)`
   2. `*.DH(public_key, secret_key) -> shared_secret`

## Construction

### API Notes

**Randomness.** All functions are deterministic. They can be turned into randomized functions in the standard way by wrapping with a function that generates the random bytes.

**Decapsulation failures.** ML-KEM is an _implicitly rejecting_ KEM, meaning that Decaps always produces a value, but in the case of decapsulation failure, the produced value is random garbage. The proposed KEMs fallthrough this behavior, and therefore are also implicitly rejecting.

**Input validation.** All inputs MUST be validated. This includes checking that elliptic curve points are on the curve and not the point at infinity, and that the hashes in the ML-KEM secret key are consistent (i.e., `ek = h`.)

FIXME(sanketh): Enumerate all the validation checks and add KATs.

### Internal Constants

All KEMs are a combination of a post-quantum KEM `PQ` and a traditional DH group `T`.

| KEM    | Shared Secret | Public Key | Secret Key | Ciphertext | Keygen Seed | Encaps Seed |
| :----- | :------------ | :--------- | ---------- | ---------- | ----------- | ----------- |
| PQ768  | 32            | 1184       | 2400       | 1088       | 64          | 32          |
| PQ1024 | 32            | 1568       | 3168       | 1568       | 64          | 32          |

| DH     | Shared Secret | Public Key | Secret Key | Keygen Seed |
| :----- | :------------ | :--------- | ---------- | ----------- |
| T25519 | 32            | 32         | 32         | 32          |
| T256   | 32            | 65         | 32         | 48          |
| T384   | 48            | 97         | 48         | 64          |

### Structures

All inputs and outputs are fixed-length byte strings.

| KEM      | Shared Secret | Public Key | Secret Key     | Ciphertext | Keygen Seed | Encaps Seed |
| :------- | :------------ | :--------- | -------------- | ---------- | ----------- | ----------- |
| PQT25519 | 32            | 1184 + 32  | 2400 + 32 + 32 | 1088 + 32  | 64 + 32     | 32 + 32     |
| PQT256   | 32            | 1184 + 65  | 2400 + 32 + 65 | 1088 + 65  | 64 + 48     | 32 + 48     |
| PQT384   | 32            | 1568 + 97  | 3168 + 48 + 97 | 1568 + 97  | 64 + 64     | 32 + 64     |

**Shared secrets.** All shared secrets are 32 byte strings.

**Public keys.** Public keys are concatenations of the PQ public key and the T public key.

**Secret keys.** Secret keys are concatentations of the PQ secret key, the T secret key, and the T public key. (We do not need to include the ML-KEM public key because the ML-KEM secret key includes it.)

**Ciphertexts.** Ciphertexts are concatentations of the PQ ciphertext and the T ciphertext (which is an ephemeral T public key).

**Keygen seeds.** Keygen seeds are concatenations of the PQ keygen seed and the T keygen seed.

**Encaps seeds.** Encaps seeds are concatenations of the PQ encaps seed and the T keygen seed.

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
   public_key = concat(pq_public_key, T.SerializePublicKey(t_public_key))
   secret_key = concat(pq_secret_key, T.SerializeSecretKey(t_secret_key), public_key)
   return (public_key, secret_key)
```

### Encapsulation

```
def EncapsDeterministic<PQ, T>(public_key, seed) -> (ciphertext, shared_secret):
   pq_public_key = public_key[..PQ_PUBLIC_KEY_LEN]
   t_public_key = T.DeserializePublicKey(public_key[PQ_PUBLIC_KEY_LEN..])
   (pq_ciphertext, pq_shared_secret) = PQ.EncapsDeterministic(pq_public_key, seed[..PQ_ENCAPS_SEED_LEN])
   (t_ephemeral_public_key, t_ephemeral_secret_key) = T.KeygenDeterministic(seed[PQ_ENCAPS_SEED_LEN..])
   t_ciphertext = T.SerializePublicKey(t_ephemeral_public_key)
   t_shared_secret = T.DH(t_public_key, t_ephemeral_shared_secret)
   ciphertext = concat(pq_ciphertext, t_ciphertext)
   shared_secret = Combiner(pq_shared_secret, t_shared_secret, t_ciphertext, t_public_key)
   return (ciphertext, shared_secret)
```

### Decapsulation

```
def Decaps<PQ, T>(ciphertext, secret_key) -> shared_secret:
   pq_ciphertext = ciphertext[..PQ_CIPHERTEXT_LEN]
   t_ciphertext = T.DeserializePublicKey(ciphertext[PQ_CIPHERTEXT_LEN..])
   pq_secret_key = secret_key[..PQ_SECRET_KEY_LEN]
   t_secret_key = T.DeserializeSecretKey(secret_key[PQ_SECRET_KEY_LEN..(PQ_SECRET_KEY_LEN + T_SECRET_KEY_LEN)])
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

FIXME(sanketh): Write formal proofs, with precise bounds.

### Post-Quantum IND-CCA Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are PRFs.
2. ML-KEM-768 and ML-KEM-1024 are IND-CCA KEMs.

#### Proof Sketch

This follows from Theorem 2 of [Barbosa et al. (2024)](https://eprint.iacr.org/2024/039). The insight, building on [Giacon et al. (2018)](https://eprint.iacr.org/2018/024) and [Petcher and Campagna (2023)](https://eprint.iacr.org/2023/972), is that the hybrid KEM is IND-CCA if the non-IND-CCA KEM's ciphertexts and public keys are hashed into the shared secret.

### Pre-Quantum Fallback IND-CCA Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are random oracles.
2. P-256, P-384, and Curve25519 are _rerandomisable nominal groups_ where the _Gap Diffie-Hellman_ assumption holds, see Sections 4.1 and 4.2 of [Alwen et al. (2020)](https://eprint.iacr.org/2020/1499).
3. ML-KEM-768 and ML-KEM-1024 are C2PRI secure, see Definition 7 and Theorem 3 of [Barbosa et al. (2024)](https://eprint.iacr.org/2024/039).

#### Proof Sketch

This follows from Theorem 1 of [Barbosa et al. (2024)](https://eprint.iacr.org/2024/039). The insight is that to break IND-CCA security, the adversary needs to find a second ML-KEM ciphertext that decrypts to the same shared secret. Specifically, given a honestly generated ML-KEM public key and ML-KEM secret key and a honestly generated ML-KEM ciphertext and ML-KEM shared secret, find a second ML-KEM ciphertext that, under the given ML-KEM secret key, decrypts to the same shared secret. And this reduces to finding a collision in the hash functions underlying ML-KEM, and if we assume that they are random oracles, then this construction is secure, even if ML-KEM is otherwise broken.

### LEAK-BIND-K-CT Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are random oracles.
2. ML-KEM-768 and ML-KEM-1024 are LEAK-BIND-K-CT secure, see Table 5 of [Cremers et al. (2023)](https://eprint.iacr.org/2023/1933).

#### Proof Sketch

Recall the LEAK-BIND-K-CT game from Figure 5 of [Cremers et al. (2023)](https://eprint.iacr.org/2023/1933). The adversary is given two honestly generated key pairs `(sk0,  pk0)` and `(sk1, pk1)` and the goal is to produce two ciphertexts `c0 != c1` such that they decapsulate under `pk0` and `pk1` respectively, to the same shared secret `ss`.

`pq*` ciphertexts are concatenations of the ML-KEM ciphertext and the DH ciphertext. Therefore, to win, the adversary would have to differ on the ML-KEM ciphertext or the DH ciphertext. The shared secret hashes the DH ciphertext, so the random oracle assumption, prevents differing on the DH ciphertext. And the LEAK-BIND-K-CT assumption on ML-KEM prevents differing on the ML-KEM ciphertext.

**ML-KEM LEAK-BIND-K-CT proof sketch.** 
This sketch is adapted from proof of Proposition 1 in [Schmieg (2024)](https://eprint.iacr.org/2024/523).

Recall ML-KEM.Decaps (Algorithm 17) in [FIPS 203 IPD](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf). We assume that `G`, `H`, and `J` are independent collision-resistant hash functions.

We have three cases, both decaps succed, one decaps fails, and both decaps fail.

_Case 1: both decaps succeed._ The adversary needs `G(m'0 || h0) = G(m'1 || h1)`.

Because the keys are honestly generated, `h0 = H(ek0)` and `h1 = H(ek1)`, and since `H` is collision-resistant, `h0 == h1` if and only if `ek0 == ek1`.

If `ek0 != ek1`, then `h0 != h1`, and since `G` is collision-resistant, this is hard.

If `ek0 == ek1 = ek`, and we assumed `G` is collision-resistant, then the adversary needs to `m'0 == m'1 = m'`. Since we assumed both decaps succeed, this means that `c0 == K-PKE.Encrypt(ek_PKE, m', r')` and `c1 == K-PKE.Encrypt(ek_PKE, m', r')`. And since `K-PKE.Encaps` is deterministic, this means `c0 = c1` which is a contradiction.

_Case 2: one decaps succeeds._ The adversary needs `G(m'0 || h0) = J(z1 || c1)`.

Since `G` and `J` are independent and collision-resistant, this is hard.

_Case 3: both decaps fail._ The adversary needs `J(z0 || c0) = J(z1 || c1)`.

Since `c0 != c1` and `J` is collision-resistant, this is hard.

#### Aside on MAL-BIND-K-CT

This scheme achieves MAL-BIND-K-CT, it hashes the DH ciphertext and Proposition 1 of [Schmieg (2024)](https://eprint.iacr.org/2024/523) shows that ML-KEM is MAL-BIND-K-CT if ML-KEM secret keys are validated, which this scheme requires.

### LEAK-BIND-K-PK Security

#### Assumptions

1. HKDF-SHA256 and HKDF-SHA384 are random oracles.
2. ML-KEM-768 and ML-KEM-1024 are LEAK-BIND-K-PK secure, see Table 5 of [Cremers et al. (2023)](https://eprint.iacr.org/2023/1933).

#### Proof Sketch

Recall the LEAK-BIND-K-PK game from Figure 5 of [Cremers et al. (2023)](https://eprint.iacr.org/2023/1933). The adversary is given two honestly generated key pairs `(sk0,  pk0)` and `(sk1, pk1)` and the goal is to produce two ciphertexts `c0` and `c1` such that they decapsulate under `pk0 != pk1` respectively, to the same shared secret `ss`.

`pq*` public keys are concatenations of the ML-KEM public key and the DH public key. Therefore, to win, the adversary would have to differ on the ML-KEM public key or the DH public key. The shared secret hashes the DH public key, so the random oracle assumption, prevents differing on the DH ciphertext. And the LEAK-BIND-K-PK assumption on ML-KEM prevents differing on the ML-KEM public key.

**ML-KEM LEAK-BIND-K-CT proof sketch.** 
This sketch is adapted from proof of Proposition 1 in [Schmieg (2024)](https://eprint.iacr.org/2024/523).

Recall ML-KEM.Decaps (Algorithm 17) in [FIPS 203 IPD](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf). We assume that `G`, `H`, and `J` are independent collision-resistant hash functions.

We have three cases, both decaps succed, one decaps fails, and both decaps fail.

_Case 1: both decaps succeed._ The adversary needs `G(m'0 || h0) = G(m'1 || h1)`.

Because the keys are honestly generated, `h0 = H(ek0)` and `h1 = H(ek1)`, and since `H` is collision-resistant and we assume `ek0 != ek1`, `h0 != h1` And since `G` is collision-resistant, this is hard.

_Case 2: one decaps succeeds._ The adversary needs `G(m'0 || h0) = J(z1 || c1)`.

Since `G` and `J` are independent and collision-resistant, this is hard.

_Case 3: both decaps fail._ The adversary needs `J(z0 || c0) = J(z1 || c1)`.

Since the keys are honestly generated, and if we assume that the RNGs underlying KeyGen are collision-resistant, `z0` and `z1` are equal if and only if the keys are equal. And since `J` is collision-resistant, this is hard.

#### Aside on MAL-BIND-K-PK

This scheme is not MAL-BIND-K-PK. It is vulnerable to the attack in Section 2.2 of [Schmieg (2024)](https://eprint.iacr.org/2024/523).

**MAL-BIND-K-PK attack sketch.** The DH part is constant and produces the same shared secret. The ML-KEM part will cause decaps failures on both sides since the ciphertexts are random bytes independent of the public keys. And since both secret keys have the same implicit rejection secret, they output the same shared secret.

```
// T part is constant
(t_pk, t_sk) = T.KeyGen()
t_ct = T.Encaps(t_pk)

// ML-KEM part is Schmieg's attack
(dk0_PKE, ek0_PKE, H(ek0_PKE), z0) = ML-KEM.KeyGen()
(dk1_PKE, ek1_PKE, H(ek1_PKE), z1) = ML-KEM.KeyGen()
z = RandomBytes()
c = RandomBytes()
dk0 = (dk0_PKE, ek0_PKE, H(ek0_PKE), z)
dk1 = (dk1_PKE, ek1_PKE, H(ek1_PKE), z)

return (
   sk0 = dk0 || t_sk
   sk1 = dk1 || t_sk
   ct  = c || t_ct
)
```

### Non-Goals

#### Authentication

These KEMs do not aim to provide authentication.

However, since they are slightly modified DHKEM, they can be easily modified to provide classical authentication. However, we choose not to do this because the resulting authenticated KEMs would be vulnerable to _key-compromise impersonation attacks_; that is, an attacker with knowledge of the recipient secret key can generate a valid ciphertext impersonating a sender, without compromising the sender's secret key, see Section 5.4 of [Alwen et al. (2020)](https://eprint.iacr.org/2020/1499).

This can be compensated for with thoughtful protocol design. see [PQXDH](https://signal.org/docs/specifications/pqxdh/) and Theorem 8 in [Bhargavan et al. (2024)](https://inria.hal.science/hal-04604518v2/document).
