# ternary-zkp

**Zero-knowledge proofs over GF(3): prove you know a ternary value without revealing it.**

Zero-knowledge proofs allow one party to prove a statement is true without revealing any information beyond the truth of the statement. This crate implements ZKP over the finite field GF(3) where arithmetic is simpler than large prime fields: every non-zero element is its own inverse (1⁻¹ = 1, 2⁻¹ = 2 mod 3), and polynomial evaluation is exact with no overflow.

---

## Why GF(3)?

**Simplicity**: GF(3) has 3 elements {0, 1, 2} with trivial arithmetic:
```
Addition: 0+1=1, 1+2=0, 2+2=1 (mod 3)
Multiplication: 1×1=1, 1×2=2, 2×2=1 (mod 3)
Inverse: 1⁻¹=1, 2⁻¹=2 (every non-zero is self-inverse!)
```

**Compact proofs**: The witness space is only {-1, 0, +1} — much smaller than typical 256-bit fields. This means proof components are smaller and verification is faster.

**No bignum needed**: All arithmetic fits in a single byte. No BigInt, no modular exponentiation with 2048-bit numbers.

---

## Architecture

- **`TernaryField`** — GF(3) arithmetic: add, sub, mul, inv, div, pow
- **`GF3Polynomial`** — Polynomials over GF(3) with evaluation and Lagrange interpolation
- **`PolynomialCommitment`** — Commit to a polynomial, verify evaluations
- **`PedersenParams`** — Setup parameters for Pedersen commitments
- **`ZKProof`** — Prove ternary statements: "I know x ∈ {-1,0,+1} such that..."
- **`ZKVerifier`** — Verify proofs without learning the witness
- **`challenge_hash()`** — Fiat-Shamir heuristic for non-interactive proofs

---

## Quick Start

```rust
use ternary_zkp::{TernaryField, GF3Polynomial, ZKProof, ZKVerifier};

// GF(3) arithmetic
let f = TernaryField(2);
assert_eq!(f.mul(&TernaryField(2)), TernaryField(1)); // 2×2=1 mod 3
assert_eq!(f.inv(), TernaryField(2)); // 2⁻¹=2 mod 3

// Polynomials
let p = GF3Polynomial::from_coeffs(vec![1, 2, 1]); // 1 + 2x + x²
assert_eq!(p.evaluate(&TernaryField(1)), TernaryField(1)); // 1+2+1=4≡1 mod 3
```

---

## Ecosystem

- **ternary-blockchain** — Blockchain using ternary hashes (verify blocks with ZKPs)
- **ternary-secret-share** — Secret sharing over Z₃
- **ternary-proof** — Proof systems for ternary statements
- **ternary-hash** — Ternary hash functions

## License

MIT
