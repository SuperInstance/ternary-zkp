# ternary-zkp

**Zero-knowledge proofs over the ternary field GF(3) — polynomial commitments, Pedersen commitments, and OR-composition Schnorr proofs for ternary value membership.**

## Background

Zero-knowledge proofs (ZKPs) allow a prover to convince a verifier that a statement is true without revealing any information beyond the statement's validity. Since Goldwasser, Micali, and Rackoff's seminal 1989 paper, ZKPs have become foundational to modern cryptography — powering privacy-preserving cryptocurrencies (Zcash), scalable blockchains (zkRollups), and authentication protocols.

`ternary-zkp` brings zero-knowledge proofs to the ternary domain. It operates over **GF(3)** — the finite field with three elements {0, 1, 2}, where 2 ≡ −1. The crate provides:

- **GF(3) arithmetic** — field operations (add, sub, mul, inv, pow)
- **Polynomials over GF(3)** — dense polynomial representation with evaluation, arithmetic, and the ternary membership polynomial (x³ − x)
- **KZG-style polynomial commitments** — structured reference string (SRS) based commitments using modular exponentiation
- **Pedersen commitments** — information-theoretically hiding commitments
- **OR-composition Schnorr proofs** — non-interactive proofs that a Pedersen commitment hides a value in {0, 1, 2} without revealing which

The design follows the CDS94 OR-proof framework with Fiat-Shamir heuristic for non-interactivity.

## How It Works

### GF(3) Field Arithmetic

`TernaryField` represents elements of GF(3) as `u8` values in {0, 1, 2}:

| Operation | Implementation |
|-----------|---------------|
| Addition | `(a + b) mod 3` |
| Subtraction | `(a + 3 − b) mod 3` |
| Multiplication | `(a × b) mod 3` |
| Inverse | `0` has no inverse; `1⁻¹ = 1`, `2⁻¹ = 2` (since 2×2 = 4 ≡ 1) |
| Negation | `(3 − a) mod 3` |

The signed view maps: `0 → 0`, `1 → +1`, `2 → −1`, matching the balanced ternary convention.

### Polynomials over GF(3)

`GF3Polynomial` is a dense representation: `coeffs[i]` is the coefficient of xⁱ. Key operations:

- **Evaluate** — Horner's method at a field element
- **Add/Sub/Mul** — standard polynomial arithmetic reduced mod 3
- **Scale** — multiply all coefficients by a scalar
- **`ternary_membership_poly()`** — returns x³ − x, the polynomial that vanishes on every element of GF(3) (Fermat's little theorem: a³ ≡ a mod 3)

### Polynomial Commitments (KZG-style)

`PolynomialCommitment` implements a simplified KZG scheme:

1. **Setup** — choose secret τ; compute SRS as `[G^(τ⁰), G^(τ¹), ..., G^(τⁿ)] mod p` where p = 10⁹+7 (prime)
2. **Commit** — `C(f) = ∏ SRS[i]^(fᵢ) = G^(f(τ)) mod p`
3. **Verify** — recompute commitment and compare

### Pedersen Commitments

`PedersenParams` defines generators `g`, `h` and prime modulus `p`. A commitment to value `x` with randomness `r`:

```
C = g^x · h^r mod p
```

This is **perfectly hiding** (any value is equally likely given C) and **computationally binding** (can't open to a different value without solving discrete log).

### OR-Composition ZK Proof

The core ZKP proves: "I know `x ∈ {0, 1, 2}` and `r` such that `C = g^x · h^r`" without revealing `x`.

**Construction** (3-branch OR-proof):

1. For each false branch `v ≠ x`:
   - Pick random `(eᵥ, sᵥ)`
   - Compute simulated announcement: `Aᵥ = h^(sᵥ) · Tᵥ^(−eᵥ)` where `Tᵥ = C · g^(−v)`

2. For the real branch `v = x`:
   - Pick random `k`; compute announcement `Aₓ = h^k`

3. Fiat-Shamir challenge: `c = Hash(C, A₀, A₁, A₂)`

4. Split challenge: `cₓ = c − Σ_{v≠x} eᵥ mod CHAL_MOD`

5. Real response: `sₓ = k + cₓ · r mod ord`

**Verification** checks:
- Challenge sum equals Fiat-Shamir hash
- Schnorr equation holds for all branches: `h^(sᵥ) = Aᵥ · Tᵥ^(cᵥ)`

## Experimental Results

The test suite validates:

- **Field arithmetic** — addition, subtraction, multiplication, inverse, negation, reduction
- **Polynomial operations** — evaluation at all field elements, add/sub roundtrip, multiplication degree, membership polynomial vanishes on {0, 1, 2}
- **Polynomial commitments** — commit/verify roundtrip, different polynomials produce different commitments
- **ZK proofs** — all three values (0, 1, 2) produce valid proofs that verify successfully
- **Tamper detection** — modifying any challenge or response causes verification to fail
- **Structural checks** — commitment in range, non-zero challenges

## Impact

`ternary-zkp` demonstrates that zero-knowledge proofs are feasible over GF(3), opening the door to:

- **Private ternary voting** — prove your vote is valid (in {−1, 0, +1}) without revealing which way you voted
- **Confidential ternary transactions** — prove a transaction amount is a valid ternary value without revealing it
- **Ternary credential systems** — prove membership in a ternary category without revealing identity

The OR-proof construction is particularly elegant in the ternary case: with exactly three possible values, the proof naturally has three branches, one of which is real and two simulated.

## Use Cases

1. **Private voting** — A room casts a ternary vote (for/against/abstain) and produces a ZK proof that the committed vote is valid (in {0, 1, 2}). The voting system verifies the proof without learning the vote value, enabling secret ballots with cryptographic guarantees.

2. **Confidential transactions** — A ternary transaction includes a Pedersen commitment to the transaction type (send/hold/receive) and a ZK proof that the type is valid. The blockchain records the commitment and proof, enabling public verification without revealing transaction details.

3. **Credential verification** — An agent proves it holds a valid ternary credential (e.g., security level −1, 0, or +1) without revealing the level. The verifier learns only that the credential is valid, not its value.

4. **Range proofs for ternary values** — The membership polynomial (x³ − x = 0 for all x ∈ GF(3)) combined with polynomial commitments enables efficient range proofs: commit to a polynomial, prove it's the membership polynomial evaluated at a committed value.

5. **Multi-party computation** — In scenarios where multiple rooms compute on shared ternary data, ZK proofs enable each room to verify others' computations without revealing inputs or intermediate values.

## Open Questions

- **Soundness in the random oracle model:** The Fiat-Shamir heuristic replaces the verifier's random challenge with a hash. The security reduction assumes the hash function is a random oracle. Should the crate support interactive proofs as well, for settings where the random oracle model is insufficient?
- **Batch verification:** Verifying multiple proofs individually is O(n). Can proofs be batched for amortized O(1) verification per proof, similar to BLS signature aggregation?
- **Lattice-based alternatives:** The current construction relies on discrete log hardness over prime fields. Should a future version explore lattice-based ZKPs (e.g., ternary Ring-LWE) for post-quantum security?

## Connection to Oxide Stack

`ternary-zkp` is the privacy and verification layer:

- **`ternary-blockchain`** — ZK proofs enable confidential transactions and private smart contracts
- **`ternary-voting`** — ZK proofs enable secret-ballot voting with cryptographic vote validity guarantees
- **`ternary-protocol`** — proof transcripts can be serialized and transmitted between agents
- **`ternary-channel`** — secure channels can transport proof data
- **`ternary-game-theory`** — ZK proofs enable games with private strategies (prove your move is valid without revealing it)

The GF(3) field aligns perfectly with the ecosystem's ternary representation, making `ternary-zkp` the natural cryptographic layer for the SuperInstance ecosystem.
