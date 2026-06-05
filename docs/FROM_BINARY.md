# From Binary to Ternary: Zero-Knowledge Proofs

## The Trap

Zero-knowledge proofs were born in a binary world: the prover knows a secret bit string, and the verifier learns whether a statement about those bits is true. Schnorr proofs work over prime-order groups. Polynomial commitments use binary fields. The CDS94 OR-proof composes binary statements: "I know the discrete log of this point OR that point."

But the natural algebraic structure for a three-valued secret isn't binary — it's GF(3), the finite field with three elements. When your secret is a trit (not a bit), proving membership in {0, 1} flattens your problem. You're proving a binary claim about a non-binary secret, which wastes the algebraic structure of the problem.

## Map to Three States

| Domain | −1 (2 mod 3) | 0 (0 mod 3) | +1 (1 mod 3) |
|--------|-------------|-------------|--------------|
| GF(3) element | 2 (≡ −1) | 0 | 1 |
| Fermat identity | a³ = a holds for ALL field elements | | |
| Commitment | value = 2 | value = 0 | value = 1 |

## From Binary to Ternary

**Before: binary membership proof**

Standard OR-proofs prove that a committed value is in {0, 1}. If your real space is {−1, 0, +1}, you shift: prove membership in {0, 1, 2} — which requires three branches in the OR-composition. The binary approach treats this as an extension, not a first-class structure.

**After: ternary membership with GF(3) algebra**

```rust
// The polynomial x³ − x vanishes on ALL of GF(3)
// Not a coincidence — it's Fermat's little theorem for GF(3)
// This means: if a commitment opens to a value where x³ ≠ x,
// the prover is lying about the value being in {0, 1, 2}
let membership_poly = GF3Polynomial::new(vec![
    TernaryField::ZERO,  // constant term
    TernaryField::NEG_ONE,  // -x
    TernaryField::ZERO,  // x²
    TernaryField::ONE,   // x³
]);
// Evaluate at any GF(3) element → 0
```

The field structure of GF(3) gives you algebraic relationships that don't exist in binary. Every element is self-inverse (a · a ≡ 1 for a ≠ 0). The polynomial x³−x characterizes exactly the set of valid field elements. This isn't an arbitrary encoding — it's the *only* three-element field, so any three-valued proof system that uses algebraic structure is naturally GF(3).

**0 is not nothing:** In binary fields, the zero element is the additive identity and nothing more. In GF(3), 0 is one of three full field elements with equal algebraic status. The CDS94 proof treats the commitment to 0 identically to commitments to 1 or 2 — all three branches use the same Schnorr logic. Zero isn't a default or a gap; it's a genuine secret value.

**Before: binary commitment**

```rust
// Prove x ∈ {0, 1} — two branches in the OR-proof
```

**After: ternary commitment**

```rust
// Prove x ∈ {0, 1, 2} — three branches
// Each branch: simulate 2 false ones, execute the real one
// The Fiat-Shamir challenge is split across 3 branches
// e₀ + e₁ + e₂ ≡ c (mod 2²⁰)
```

All three branches are equal participants. The proof that x ∈ {0, 1} (binary) is strictly less expressive than the proof that x ∈ {0, 1, 2} (ternary), but the cost is only one extra branch — 50% more work for 50% more expressiveness.

## Why It Matters

Ternary ZK proofs match the algebraic structure of three-valued secrets. GF(3) is the only field with three elements, and its nice properties (self-inverses, vanishing polynomial x³−x) make it a natural home for trit-based cryptography. Proving membership in a three-element set is the atomic unit of ternary ZK, just as proving membership in {0, 1} is the atomic unit of binary ZK. The step from two branches to three is small; the step in expressiveness is large.
