# Cryptography in Molterra

Every primitive this product actually uses, what it is supposed to guarantee,
what an attacker provably cannot do if the guarantee holds, and where our
implementation falls short of it. Written to be read two ways: the plain-language
paragraph first, then a **Formally** box for a reviewer who wants the definition
and the standard.

Three rules govern this document.

1. **Only shipped code appears in the inventory.** Every claim names the file
   and function it came from. If it lives in `security/src/defenses/`, it is
   labeled *proposed* and is not deployed.
2. **A named primitive is not a security property.** "We use AES-256-GCM" says
   nothing about whether nonces repeat or whether ciphertexts are bound to the
   row they sit in. Those are separate claims, made separately below.
3. **No certification is claimed.** Nothing here has been validated under
   FIPS 140-3, evaluated against CNSA 2.0 as a compliance exercise, or reviewed
   by any government body. Where we cite NIST or NSA guidance it is as a
   published benchmark to measure ourselves against — including where we do not
   meet it. A product that claimed otherwise on the strength of a document it
   wrote about itself would be telling you something false.

Executable counterpart: [`ATTACKS.md`](ATTACKS.md) (991 attacks, per-attack
offense and observed defense), [`FINDINGS.md`](FINDINGS.md),
[`ADAPTATION.md`](ADAPTATION.md), [`PENTEST.md`](PENTEST.md).

---

## 1. Inventory

| # | Primitive | Where | Protects | Corpus coverage |
|---|---|---|---|---|
| P-1 | AES-256-GCM (`aes-gcm` 0.10) | `backend/src/integrations/crypto.rs` | OAuth access/refresh tokens, TOTP secrets, memory content columns | 54 attacks (`VLT-*`) |
| P-2 | HKDF-SHA-256 (`hkdf` 0.12) | `backend/src/memory/keys.rs` | Per-tenant key separation for memory content | — (reasoned below) |
| P-3 | Argon2id v19 (`argon2` 0.5) | `backend/src/auth/mod.rs` | Passwords at rest | — |
| P-4 | SHA-256 (`sha2` 0.10) | `backend/src/auth/mod.rs` | Refresh tokens and API keys at rest | 14 attacks (`CRD-*`) |
| P-5 | SHA-256 over a 6-digit space | `backend/src/auth/code.rs` | Email login codes at rest | 14 attacks (`CRD-*`) |
| P-6 | HMAC-SHA-256 + constant-time compare | `backend/src/integrations/nango_routes.rs` | Inbound webhook authenticity | — |
| P-7 | HS256 JWT (`jsonwebtoken` 9) | `backend/src/auth/mod.rs` | Access tokens, MFA challenge tokens | — |
| P-8 | TOTP HMAC-SHA-1 (RFC 6238) | `backend/src/auth/mfa.rs` | Second factor | — |
| P-9 | CSPRNG (`rand` 0.8 `ThreadRng`, `OsRng`, `uuid` v4) | throughout | Nonces, salts, codes, tokens | indirectly |
| P-10 | TLS | terminated by the platform in front of the app | Data in transit | not tested here |

"Corpus coverage: —" means **no attack rows exist yet**. It does not mean
"secure"; it means untested by this crate, and it is tracked as a gap in §7.

---

## 2. P-1 · AES-256-GCM — credentials and content at rest

**In plain terms.** Encryption alone hides content but does not stop tampering:
flip a bit of a stream cipher's output and the plaintext changes with it,
silently. AES-GCM is *authenticated* encryption — it produces a 128-bit tag, and
decryption returns an error rather than plaintext if a single bit of the
ciphertext, the tag, or the nonce is wrong. So a database attacker who can write
to a token column cannot use that write to change what the application later
reads; they can only destroy it.

Molterra stores the result as `base64(nonce‖ciphertext‖tag)` with a fresh random
96-bit nonce per message.

> **Formally.** AES-256-GCM is an AEAD scheme targeting IND-CPA + INT-CTXT,
> which together give IND-CCA2. AES-256 is modeled as a PRP on 128-bit blocks;
> GCM is counter mode (a PRF-based stream, per lecture 03–04: encryption from a
> PRF) composed with GHASH, a polynomial universal hash over GF(2¹²⁸), used as a
> Carter–Wegman MAC. The tag forgery bound is ≈ 2⁻¹²⁸ per attempt for a full
> 16-byte tag. Standard: NIST SP 800-38D; FIPS 197 for the block cipher.
> **The security proof is conditioned on nonce uniqueness per key.** See §2.2.

### 2.1 What the corpus establishes

54 executed attacks against the real byte format (see
[`attacks/vault.md`](attacks/vault.md)). The tag does its job in every category
we could construct:

| Attack | Shipped result |
|---|---|
| flip one ciphertext bit (each byte position) | **Blocked** — `decrypt: aead::Error` |
| zero the tag / drop a tag byte | **Blocked** |
| pair a ciphertext with another message's nonce | **Blocked** |
| decrypt under a different key | **Blocked** |
| truncate the stored value | **Blocked** |
| store non-base64 / a plausible forged blob | **Blocked** |
| **copy a valid ciphertext into another account's, org's, or field's row** | **Landed** |

The last row is the finding, and it is not a flaw in AES-GCM. GCM authenticates
*the message*. It does not authenticate *where the message is stored*, because
nothing told it where that was. With one key covering the table, a ciphertext is
a valid ciphertext everywhere in the table.

> **Formally.** AEAD takes associated data `A` that is authenticated but not
> encrypted; the tag is computed over `(C, A)`, so decryption under a different
> `A` fails. Passing `A = ε` — as the shipped call does, via `cipher.encrypt`
> with no AAD — makes the ciphertext context-free. The property being violated is
> not confidentiality but *binding*: a copy-and-paste attack inside the trust
> boundary of one key.

**Proposed fix (`security/src/defenses/vault.rs`, not deployed).**
`hardened_encrypt(key, plaintext, Binding { org_id, account_id, field })` feeds
the binding as AAD, so a transplanted ciphertext fails the tag check under the
destination row's binding. All four transplant rows flip to Blocked
(`F-VLT-01`, closed by hardening → adaptation `A-1`).

### 2.2 The nonce ceiling — open, and honestly so

Random 96-bit nonces collide by the birthday bound. A repeat under one key is
not a degradation; it is a break: two ciphertexts under the same keystream give
`C₁ ⊕ C₂ = P₁ ⊕ P₂`, and GHASH's authentication key becomes recoverable, so
forgery follows. `VLT-0054` stages exactly this and recovers plaintext by XOR —
**Landed, and still Landed under the hardened path** (`F-VLT-02`, deliberately
open). AAD does not help: two messages with the *same* binding can still draw
the same nonce.

> **Formally.** With `q` messages under one key and 96-bit random nonces,
> `Pr[collision] ≈ q²/2⁹⁷`. NIST SP 800-38D §8.3 caps a key at `2³²` invocations
> for random nonces. Our per-key message count is not counted, capped, or
> alerted on anywhere. The options are a counted budget with rotation at a
> declared ceiling, a deterministic nonce (SP 800-38D §8.2.1), or
> AES-GCM-SIV (RFC 8452), which degrades to leaking only equality of repeated
> plaintexts instead of collapsing.

This is the most interesting entry in the whole document, because it is the case
where the primitive is modern, the library is correct, the tag rejects
everything we throw at it — and the guarantee still depends on an operational
counter nobody is keeping.

---

## 3. P-2 · HKDF-SHA-256 — one master key, independent tenant keys

Memory content is encrypted under a key derived per tenant:
`HKDF-SHA256(ikm = master, salt = tenant_uuid_bytes, info = "molterra-memory-v1")`
(`backend/src/memory/keys.rs`). Ciphertext columns carry an `enc:v1:` prefix;
unprefixed values are legacy plaintext and pass through, so the rollout is
decrypt-if-prefixed. The master key is `Option`: absent means encryption at rest
is off and a boot warning is logged, rather than a key being invented.

**In plain terms.** One stolen tenant key reveals nothing about the master key
or about any other tenant, and a wrong tenant's key fails the GCM tag rather
than returning someone else's data.

> **Formally.** HKDF is extract-then-expand (RFC 5869): `PRK = HMAC(salt, ikm)`,
> then `OKM = HMAC(PRK, info‖counter)`. Under HMAC-as-PRF, outputs on distinct
> salts are computationally independent — this is the PRF/GGM property from
> lecture 04 used as key separation. Version-tagged `info` is what makes
> rotation to `-v2` a well-defined re-derivation rather than a guess.

Two honest boundaries stated by the code itself:

- **Content is encrypted; indices are not.** Columns the memory arms query
  lexically stay plaintext under RLS. Searchable encryption is deferred, not
  claimed.
- **Encryption at rest is not tenant isolation.** Isolation is Postgres RLS
  (contract C-1.1.a in the product's contracts register, gated by the
  database-backed CI job), not this key schedule.

**Key separation elsewhere is enforced by a panic, not by derivation.**
`INTEGRATION_ENC_KEY` must be explicit 64-hex in production or the process
refuses to boot; only in development is a key derived from `JWT_SECRET`
(`backend/src/config.rs`). The reasoning is recorded in the code: deriving the
data key from the signing secret would couple two unrelated secrets, so a
JWT-secret leak would also leak every stored OAuth token. **Gap:** no attack row
asserts the production panic, so this is a reviewed claim, not a tested one.

---

## 4. P-3 · Argon2id — passwords

`Argon2::default()` with an `OsRng` salt, i.e. Argon2id, version 19, and
`m = 19456 KiB, t = 2, p = 1`.

**In plain terms.** A password hash should be slow and memory-hungry so that a
stolen table cannot be cracked cheaply on GPUs. Argon2id is the current
recommendation for exactly this, and every hash gets its own random salt so one
precomputed table cannot cover two users.

> **Formally.** Argon2id (RFC 9106) is a memory-hard KDF; the parameters above
> are RFC 9106 §4's *second recommended* option (19 MiB, 2 passes). Salting
> destroys the amortization that makes rainbow tables work — the same reason
> §5's login codes are broken, since a 6-digit code has no entropy for a salt to
> protect. Comparison happens inside `PasswordVerifier`, which uses a
> constant-time equality internally.

**Gap:** parameters are the library default rather than a pinned, tested
constant. A dependency bump could change work factors with nothing failing.

---

## 5. P-4 / P-5 · SHA-256 at rest — the same hash, once right and once wrong

The same function, `hash_token(raw) = hex(SHA-256(raw))`, protects two very
different things. This contrast is the clearest cryptographic lesson in the
codebase.

### 5.1 Right: opaque refresh tokens and API keys

Refresh tokens are minted as two concatenated UUIDv4s (64 hex chars) and only
the SHA-256 digest is stored (`backend/src/auth/routes.rs::mint_refresh_token`).
A stolen digest is useless: there is nothing to enumerate.

> **Formally.** Preimage resistance of SHA-256 is ~2²⁵⁶ generically, but the
> real bound is the *input distribution*: two UUIDv4s carry 2 × 122 = **244
> bits** of randomness. Brute force is out of reach by an enormous margin, so an
> unsalted, un-iterated hash is the correct and cheapest choice here.
> **Nit worth fixing:** the doc comment calls this a "256-bit opaque token"; it
> is 244 bits, because 6 bits per UUID are version/variant constants. Nothing is
> weakened — it is a claim that should match the arithmetic.

### 5.2 Wrong: six-digit email login codes

`code_hash(email, code) = SHA-256("{email}:{code}")`, over a code drawn from
`0..1_000_000` (`backend/src/auth/code.rs`). Online guessing is properly
defended: 5 attempts, 10-minute TTL, 4 sends per 15 minutes, enumeration-safe
responses by default. The corpus confirms online guessing is **Blocked**.

Offline is a different story, and the attack is run for real rather than argued:

| Attack | Candidates computed | Shipped result |
|---|---|---|
| enumerate the space from one stolen digest | ≤ 10⁶ | **Landed** — live code recovered |
| worst case in the space (`999999`) | 10⁶ | **Landed** |
| bounded budget | as declared | **Landed** |
| one precomputed table reused across accounts | amortized | **Landed** |
| online guessing within the ceiling | 5 | **Blocked** |

> **Formally.** The attempt ceiling is an *online* control; it constrains queries
> to the server, not computation by an attacker holding the row. With `H`
> unkeyed, `Pr[recover] = 1` at cost 10⁶ SHA-256 evaluations — milliseconds. The
> defect is not SHA-256's; it is that a hash over a low-entropy domain is a
> *commitment anyone can open*. The property we actually need is a keyed PRF, so
> the row is a commitment only the server can open (lectures 03–04).

**Proposed fix (`security/src/defenses/credential.rs`, not deployed).**
HMAC-SHA-256 under a server-side pepper held outside the database, with the
preimage length-prefixed (`u32(len(email))‖email‖code`) so `("a@b","1:23456")`
and `("a@b:1","23456")` cannot collide, and constant-time comparison. Enumeration
then requires the pepper: unbounded work without it. All offline rows flip to
Blocked (`F-CRD-02`…`F-CRD-04`, `F-CRD-01`; adaptation `A-2`).

**Same shape, untested, worth flagging:** MFA recovery codes are 5 random bytes
(**40 bits**) stored under the same bare `hash_token` (`auth/mfa.rs`). 2⁴⁰
SHA-256 evaluations is a feasible offline search against a stolen row. No attack
row exists for it yet — it is a code-reading observation, listed in §7.

### 5.3 Comparison timing

Shipped verification compares digests with Rust's `!=` on `String`
(`code.rs`, the `verify` handler), which carries no constant-time contract. `CRD-0013` models a
byte-serial comparison and reports a prefix-length oracle. It is explicitly
labeled **surrogate, not measured** — we did not time the shipped binary, and
the row must not be read as evidence of an exploitable timing channel. Severity
is Low deliberately. The correct comparison already exists elsewhere in the
codebase (§6), which is the argument for using it here too.

---

## 6. P-6 / P-7 / P-8 · Authenticity: webhooks, tokens, second factor

**P-6 — inbound webhooks, done correctly.**
`verify_nango_signature` computes HMAC-SHA-256 over the raw body and compares
with `constant_time_eq`, refusing outright when the secret is empty. This is the
reference example in the codebase of a MAC verified without a timing channel.

> **Formally.** HMAC is a PRF-based MAC, unforgeable under chosen-message attack
> (lecture 05) assuming the compression function behaves as a PRF; NIST FIPS 198-1
> / SP 800-107. Verification must be constant-time, or the comparison itself
> becomes a forgery oracle — which is why §5.3 matters.

**P-7 — JWT access tokens.** HS256 (`Header::default()`) over claims
`{sub, org, exp}`, signed with `JWT_SECRET`, validated with
`Validation::default()` — which pins the algorithm to the one requested and
requires `exp`, so the classic "alg: none" and RS256→HS256 confusion attacks do
not apply here. Access TTL 60 minutes; refresh 30 days. MFA challenge tokens are
separate 5-minute JWTs under a suffixed secret (`{jwt_secret}::mfa-challenge-v1`),
so neither token type validates as the other. Suffix concatenation is weaker
domain separation than an HKDF `info` label — with HMAC it is adequate, but it
is the kind of thing that should read `derive`, not `format!`.

Honest limits: a symmetric MAC means every verifier can also mint (fine for one
service, not for third-party verification), and a valid unexpired access token
cannot be revoked mid-window — revocation acts on the refresh token. Both are
design positions, not accidents, and both are untested by the corpus.

**P-8 — TOTP.** RFC 6238 with HMAC-**SHA-1**, 6 digits, 30-second step, ±1 step
of drift; the shared secret is stored AES-GCM-encrypted, and a used step is
recorded in `mfa_last_totp_step` with a monotonic `<` guard so a code cannot be
replayed inside its window. SHA-1 here is the RFC 6238 default and interoperates
with every authenticator app; HMAC-SHA-1 is not affected by SHA-1's collision
weakness (collisions are irrelevant to a keyed MAC on a 6-digit truncation), so
this is a compatibility choice rather than a weakness — but it *is* SHA-1, and a
reviewer benchmarking against CNSA 2.0 should see it named rather than buried.

---

## 7. Randomness, and what would actually be catastrophic

| Use | Source | Assessment |
|---|---|---|
| Argon2 password salts | `argon2::password_hash::rand_core::OsRng` | OS CSPRNG — correct |
| GCM nonces (P-1) | `rand::thread_rng()` | `ThreadRng` is a ChaCha12 CSPRNG seeded from OS entropy and periodically reseeded — cryptographically adequate; nonce *uniqueness* (§2.2), not quality, is the open issue |
| 6-digit login codes | `rand::thread_rng().gen_range(0..1_000_000)` | uniform over the space; the space itself is the problem |
| Refresh tokens / API keys | `uuid` v4 (OS entropy) | 244 bits — ample |
| MFA recovery codes | `rand::thread_rng().fill_bytes([u8; 5])` | 40 bits — thin for an offline-attackable digest (§5.2) |

Nothing in this repository implements a cryptographic primitive. Every primitive
is a vetted crate (`aes-gcm`, `hkdf`, `argon2`, `hmac`, `sha2`, `jsonwebtoken`,
`totp-rs`, `constant_time_eq`), and `memory/keys.rs` states the rule explicitly:
*zero cryptographic primitives are implemented here — composition only.* Every
finding in this document is a composition or operational error, which is the
usual place real systems fail.

---

## 8. Standards alignment — including where we do not meet it

| Guidance | Requirement | Molterra | Verdict |
|---|---|---|---|
| FIPS 197 / SP 800-38D | AES-256, GCM, 96-bit nonce, 128-bit tag | as specified | **Meets** |
| SP 800-38D §8.3 | ≤ 2³² invocations per key with random nonces | not counted or capped | **Does not meet** (`F-VLT-02`, open) |
| SP 800-38D (AAD input) | bind context via associated data | no AAD | **Does not meet** (`F-VLT-01`; fix proposed, not deployed) |
| RFC 5869 | extract-then-expand, version-tagged `info` | as specified | **Meets** |
| RFC 9106 | Argon2id, second recommended parameters | matches (library default) | **Meets**, unpinned |
| SP 800-63B §5.1.1 | short out-of-band secrets rate-limited; secrets at rest protected against offline attack | rate limits present; digest is unkeyed | **Partially** (`F-CRD-02`, fix proposed) |
| SP 800-107 / FIPS 198-1 | HMAC for authenticity, constant-time verification | webhooks yes; login-code compare no | **Mixed** (§5.3) |
| RFC 6238 | TOTP, replay prevention | yes, SHA-1 default | **Meets** |
| NSA CNSA 2.0 | AES-256; SHA-384/512 for hashing; ML-KEM/ML-DSA for asymmetric | AES-256 yes; SHA-256 not SHA-384; HS256 JWT; no post-quantum anywhere | **Does not meet** — and we do not claim to |

On that last row, plainly: CNSA 2.0 is a suite for protecting US national
security systems, with an algorithm profile and a validation regime. Molterra
uses several of the same primitives at comparable key sizes. It has not been
validated, is not post-quantum, and is not equivalent. Our symmetric choices are
strong; SHA-256's 128-bit collision resistance is far beyond any practical
attack on the uses here, and moving to SHA-384 would be alignment work, not a
fix for a break. Post-quantum migration is not started, and matters most for
TLS (platform-owned) rather than for data at rest under AES-256.

---

## 9. Curriculum map

Where the theory actually bites, and — just as important — where it does not
yet.

| Topic | In this product |
|---|---|
| Perfect secrecy, one-time pad, Shannon's bound | Why key reuse is fatal, demonstrated concretely: `VLT-0054` is a two-time pad, recovered by XOR (§2.2) |
| Computational security, PRGs | The CSPRNG table in §7; every nonce, salt, and token depends on it |
| PRFs, encryption from a PRF, GGM | GCM's counter-mode keystream; HKDF's per-tenant separation (§3); the keyed-hash fix in §5.2 |
| IND-CPA | Fresh nonce per message ⇒ ciphertexts of equal plaintexts differ (asserted by a shipped backend test) |
| MACs, authentication, CCA security | GHASH tags (§2), HMAC webhooks (§6), HS256 JWTs; the 54 tamper rows are CCA attempts, all Blocked |
| One-way functions, hard-core bits | The digest-at-rest model in §5; one-wayness is worthless over a 10⁶ domain |
| Collision-resistant hashing | The length-prefixing fix in §5.2 — an encoding ambiguity, not a hash break (`F-CRD-01`) |
| Public-key crypto, key exchange, RSA | **Not implemented.** Present only inside TLS, which the platform terminates |
| Digital signatures | **Not implemented** in the asymmetric sense; token authenticity is symmetric (HS256) |
| Identity-based encryption | **Not implemented** |
| Zero knowledge | **Not implemented.** Adjacent in spirit only: the composition fence tries to admit a claim while revealing no ungrounded content (§10) |
| Secret sharing, OT, GMW, Yao, BGW, FHE | **Not implemented.** The honest design note: searchable encryption over encrypted memory indices (§3) is where such tooling would first be relevant, and it is deferred |

The bottom half of that table is deliberately empty. A trust center that
claimed FHE or zero-knowledge proofs because the words are impressive would be
lying; the table exists so that a reviewer can see the boundary of what we
actually run.

---

## 10. Adjacent, and not cryptography — the fences

923 of the 991 attacks target something no cipher can help with: text that
crosses the record boundary into a model prompt. Invisible code points
(U+200B, the U+E00xx tag block), bidi overrides, homoglyphs, fullwidth and
mathematical alphanumerics, separators, base64, ROT13 — all attempts to carry an
instruction past `injection_line` and `verify_composition`. Confidentiality and
integrity of bytes are irrelevant there: the payload is *authentic*, correctly
encrypted, and hostile. Those results, per attack, are in
[`attacks/injection.md`](attacks/injection.md),
[`attacks/steganography.md`](attacks/steganography.md), and
[`attacks/composition.md`](attacks/composition.md); the normalization defense is
`security/src/defenses/normalize.rs` (proposed).

Two findings remain open there on purpose (`F-CMP-09`, `F-CMP-21`): a sentence
can be false while every token in it is grounded in an approved fact. The
citation fence enforces grounding, not truth. No amount of cryptography closes
that, and pretending otherwise would be the same category error as claiming
AES-GCM prevents a copy-paste transplant.

---

## 11. Open cryptographic gaps

| Gap | Status |
|---|---|
| No per-key GCM message budget or rotation trigger (§2.2) | `F-VLT-02`, adaptation `A-7` — **open** |
| Ciphertexts not bound to (org, account, field) | `F-VLT-01` — fix written, **not deployed** |
| Login-code digests unkeyed and offline-enumerable | `F-CRD-02`…`04` — fix written, **not deployed** |
| Login-code comparison not constant-time | `F-CRD-05`, Low, surrogate evidence only |
| 40-bit MFA recovery codes under a bare SHA-256 | observed by review, **no attack row yet** |
| Production key-separation panic untested | reviewed, **no attack row** |
| Argon2 parameters unpinned (library default) | **open** |
| JWT/TOTP/session flows have no attack rows | tracked in `PENTEST.md` §3 |
| Searchable encryption over memory indices | explicitly deferred |
| No post-quantum migration | not started |
| SHA-256 rather than SHA-384 where CNSA 2.0 prefers the latter | alignment gap, not a break |

Three of those rows already have executable fixes in `security/src/defenses/`
waiting on promotion; the rest are review observations or design decisions. The
document is written so that when a fix ships, the change is visible here as a
line moving from *proposed* to *shipped* — not as an adjective quietly upgraded.
