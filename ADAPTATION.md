# Adaptation log

How a landing attack becomes a product change. Each entry names the finding
rows in [`FINDINGS.md`](FINDINGS.md) that motivate it, the hardened code in
`src/defenses/` that demonstrates the fix, what it costs, and where it stands.
The status column uses the vocabulary of the product's contracts register: the
hardened layer is **evidence**, not enforcement, until a product change
promotes it and adds the contract entry.

| # | Adaptation | Closes | Demonstrated in | Status |
|---|---|---|---|---|
| A-1 | Bind vault ciphertexts to their row with AAD | F-VLT-01 | `defenses::vault::hardened_{encrypt,decrypt}` | proposed |
| A-2 | Key the login-code digest | F-CRD-01..05 | `defenses::credential::hardened_code_hash`, `constant_time_eq` | proposed |
| A-3 | Normalize before detecting | F-INJ-*, F-STG-*, F-CMP-* except 09 and 21 | `defenses::normalize` | proposed |
| A-4 | Strip invisible code points at the record boundary | F-STG-09 and every `in keyword` row | `defenses::normalize::is_invisible`, `defenses::compose` | proposed |
| A-5 | Close the provider-label channel | F-STG-39 | `defenses::normalize::source_label` | proposed |
| A-6 | Give `backend` a lib target so the mirrors can be deleted | (test-integrity) | — | proposed |
| A-7 | Per-key message budget and rotation for the vault | F-VLT-02 | — | **open** |
| A-8 | Proposition-level grounding | F-CMP-09, F-CMP-21 | — | **open**, out of scope for this layer |

## A-1 — bind vault ciphertexts to their row

**What lands.** `VLT-0001..0004`: a ciphertext produced for one
`(org, account, field)` decrypts unchanged when presented as another's. The
attacker needs write access to `integration_accounts` and nothing else.

**The change.** AES-GCM already takes associated data; the shipped call passes
`b""`. Pass `len(org) || org || len(account) || account || len(field) || field`
instead. The stored blob is byte-for-byte the same shape — AAD is authenticated,
not stored — so there is no migration of the ciphertext column, only a
re-encryption pass or a dual-read window while old rows are rebound.

**What it costs.** `decrypt` needs the row identity at the call site, so its
signature grows. The one place that decrypts (`backend/src/integrations/`)
already has the row. A restore from backup that moves a row between accounts
now fails to decrypt instead of silently working — which is the point, and also
a behavior change operators must know about.

**Contract.** New entry in §1 alongside the token-store rows, L2, enforced by
this corpus's transplant attacks running against the real function once A-6
makes that possible.

## A-2 — key the login-code digest

**What lands.** `CRD-0001..0004` and `CRD-0007`: `sha256("{email}:{code}")`
over a 10⁶ space is recovered offline from a single stolen row, worst case
included; `CRD-0013` records that the shipped verify compares digests with
`String !=`, which has no constant-time contract — that row is a byte-serial
model of the compare's contract, not a timing measurement of the shipped
binary, and is rated low for that reason; `CRD-0014` shows the `:` separator makes `("a:b", "c")` and `("a", "b:c")`
collide.

**The change.** `HMAC-SHA-256(pepper, len(email) || email || code)` with a
pepper the database never holds, and `subtle::ConstantTimeEq` on the hex
digests. The pepper is a new secret with the same handling as
`INTEGRATION_ENC_KEY`: required in production, derived with a loud warning in
dev.

**Why not just a slower hash.** Argon2 over a six-digit space buys a constant
factor; the attacker still enumerates a million candidates and the defender
pays the same cost per legitimate login. A key makes the row *insufficient*
rather than *expensive*, which is the property the online five-attempt limit
was already assuming the store had.

**What it costs.** Codes issued before the cutover cannot be verified after it.
They live ten minutes; drain the window and rotate.

## A-3 — normalize before detecting

**What lands.** 492 injection rows and most steganography rows — every one is
the same 18 instructions with one of 34 transformations applied
(`corpus::evasion::ALL`). The shipped `injection_line` is a literal match and
has no normalization stage at all, so any confusable, any inserted separator,
any encoding, defeats it.

**The change.** `defenses::normalize::fold` runs before the existing checks:
strip invisibles, fold Cyrillic/Greek/fullwidth/enclosed/mathematical
confusables to ASCII, collapse Unicode whitespace, undo separator insertion
and conservative leetspeak, and inspect ROT13, reversed, and base64-decoded
views of the line. The existing phrase and keyword-pair tables run over the
folded text unchanged.

**What it costs.** False positives, and they are measured rather than asserted:
`mirror_tests::the_hardened_layer_leaves_ordinary_records_alone` requires
identical verdicts to the shipped fence on ordinary prose including `Q3
revenue was $150,000`, *"please disregard my earlier estimate"*, and a line
that legitimately mentions a "system prompt" — the hardening may not flag
anything the shipped code lets through. The conservative leetspeak rule (`deleet`) exists because the
first version ate `3rd` and `Q3`; that regression is now a unit test. Expect
the fold to be tuned against the capture eval fixtures before promotion.

**Contract.** Extends P11–P14 in `fence/`; the SPARK port would need the same
normalization stage, which is the argument for landing it in Rust first and
letting the shadow period find the disagreement.

## A-4 — strip invisible code points at the record boundary

**What lands.** The invisible-carrier steganography rows: zero-width characters, the
byte-order mark, soft hyphens, directional overrides, variation selectors, and
above all the **Unicode tag block** (`U+E0000..E007F`), which is a complete
invisible alphabet. `sanitize_excerpt` preserves all of them because they are
neither control characters nor whitespace.

**The change.** Reject or strip `Cf`-class and tag-block code points at
`sanitize_excerpt`, `sanitize_span`, and in `verify_composition` before any
other check. Stripping is enough for the excerpt; the composition path should
*reject*, because an invisible character in a sentence the product is about to
show a user means the model's output was not the model's — it echoed a payload.

**What it costs.** The strip list includes `U+200D` ZERO WIDTH JOINER, which
is load-bearing in Indic conjuncts and emoji ZWJ sequences, so an excerpt
containing either is altered. The hardened layer accepts that cost for the
excerpt path because the excerpt is context for a model, not text shown back to
the user verbatim; whether it is acceptable for the span (a title) needs the
capture eval fixtures with non-Latin content before promotion. This is the
known false-positive surface of A-4 and it is not yet measured.

## A-5 — close the provider-label channel

**What lands.** `source_label` accepts any lowercase ASCII token up to 24 bytes,
so the label the model sees ("from `slack`") is attacker-controlled: `system`,
`ignore-all-prior-rules`, and confusable `ѕlack` all pass.

**The change.** An allowlist of the providers the product actually integrates
with, non-ASCII rejected before folding, everything else `workspace record`.

**What it costs.** Adding a provider means adding a line. That is the cost we
want.

## A-6 — give `backend` a lib target

`backend/` is binary-only, so the vault and credential corpora attack mirrors
of `integrations/crypto.rs` and `auth/code.rs` rather than the functions. The
mirrors are pinned by `tests/mirror_tests.rs` (wire format, rejections, exact
digest computed independently of the mirror) but a mirror is still a claim.
Splitting `backend` into `lib.rs` + `main.rs` lets the corpus import the real
functions and lets A-1 and A-2 be **L2** against production code instead of L2
against a restatement of it. No behavior change; a build-shape change.

## A-7 — per-key message budget (open)

**What lands.** `VLT-0054`, and it lands in **both** columns on purpose. Two
encryptions under the same key and nonce leak `P₁ ⊕ P₂`; with one plaintext
known the other falls out. AAD changes nothing here because confidentiality is
gone before the tag is checked.

**Why it is open.** The shipped code draws a random 96-bit nonce per message,
which is correct, and the collision probability is `n² / 2⁹⁷`. That is
negligible for a token store — NIST's 2⁻³² bound is reached at about 2³² messages
under one key — but *negligible under a budget* is the actual guarantee, and
nothing enforces the budget. The corpus stages the collision rather than finding
it, and refuses to record it as closed.

**The change that would close it.** Either a per-key encryption counter with
rotation at a declared ceiling (a contract entry stating the ceiling and its
derivation, per the θ rule in `AGENTS.md`), or AES-GCM-SIV, which survives
nonce reuse with only equality leakage. The second is the smaller diff.

## A-8 — proposition-level grounding (open, by design)

**What lands.** `CMP-0024` asserts a counterparty and deadline using only
lowercase words with no numbers; `CMP-0025` says *"the renewal is not due Nov
14"* about a fact that says it is. Every token is grounded. The proposition is
false.

**Why it is open.** `verify_composition` is a token-grounding fence: it checks
that numbers, proper nouns, dates, and quotes in the sentence appear in the
cited evidence. That is P1–P8 and it holds. It was never a truth oracle, and the
hardened composition layer here does not pretend to be one — a defense that
claimed to catch `CMP-0025` with more regexes would be the overstatement
`AGENTS.md` forbids. The register carries these two rows so that no one reads
"53 composition attacks, 51 blocked" as "the fence verifies meaning".

**What would move it.** An NLI or entailment check between the sentence and the
cited fact text, run as a fourth stage after grounding, with its own calibration
and its own false-reject rate on the eval set. That is a model, not a fence, and
it belongs in the gate's scoring path (`capture/src/assist/gate.rs`), not in
`verify_composition`.

## Adding to this log

An entry is written when a row lands on the shipped column. It does not close
until the row's hardened column blocks *and* the change has a promotion path
named. The corpus is the source of truth for the first half; a reviewer is the
source of truth for the second. Do not edit a row's expected verdict to make an
entry close — `corpus_tests::the_record_matches_the_code` will tell you when the
code has moved, and that is the moment to decide whether the register or the
code is right.
