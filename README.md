# ternary-zkp

> Zero-knowledge proofs over the ternary field GF(3).

---

## What problem does this solve?

In privacy-preserving cryptography a prover often must convince a verifier that a committed value belongs to a small set without revealing the value itself.  This crate implements a **non-interactive zero-knowledge proof** that a Pedersen commitment hides an element of the finite field GF(3)—i.e. $x \in \{0,1,2\}$—using a CDS94 OR-composition of Schnorr proofs and the Fiat–Shamir heuristic.  It also provides dense polynomial arithmetic over GF(3) and a KZG-style polynomial commitment scheme.  Together these primitives give students a complete, minimal stack for understanding ZK reasoning on ternary data.

---

## Mathematical foundations

### GF(3) arithmetic

GF(3) is the finite field with three elements $\{0,1,2\}$ where $2 \equiv -1 \pmod 3$.

- **Addition / subtraction** are performed modulo 3.
- **Multiplication** is ordinary integer multiplication modulo 3.
- **Inverses**: every non-zero element is its own inverse because $1 \cdot 1 \equiv 1$ and $2 \cdot 2 = 4 \equiv 1 \pmod 3$.
- **Negation**: $\operatorname{neg}(a) = (3 - a) \bmod 3$.

The type `TernaryField` stores elements canonically as `0, 1, 2` and provides all field operations.

### Polynomials over GF(3)

`GF3Polynomial` stores coefficients in dense form: `coeffs[i]` is the coefficient of $x^i$.

- **Evaluation** is Horner-like accumulation in the field.
- **Addition / subtraction** are point-wise modulo 3.
- **Multiplication** is the standard convolution, again reduced modulo 3.

A key identity is **Fermat’s little theorem** over GF(3): for every $a \in \mathrm{GF}(3)$ we have $a^3 = a$.  Consequently the polynomial $x^3 - x$ vanishes on the entire field.  This polynomial is exposed as `ternary_membership_poly()` and is the algebraic reason why a value in $\{0,1,2\}$ can be proved with a degree-3 relation.

### KZG-style polynomial commitment

The crate implements a **structured-reference-string (SRS) commitment**:

1. **Setup** chooses a secret $\tau$ and publishes $\mathsf{srs}[i] = G^{\tau^i} \bmod P$.
2. **Commit** to $f(x) = \sum f_i x^i$ by computing $C = \prod \mathsf{srs}[i]^{f_i} = G^{f(\tau)} \bmod P$.

Because the discrete logarithm of $G$ base $P$ is unknown, the prover cannot open the commitment to two different polynomials.  Verification simply recomputes $C$ and checks equality.

### Pedersen commitments and CDS94 OR-proofs

A **Pedersen commitment** to a value $x$ with randomness $r$ is $C = g^x \cdot h^r \bmod p$.  It is perfectly hiding and computationally binding.

To prove $x \in \{0,1,2\}$ without revealing $x$, we use the **CDS94** technique:

- For each possible value $v \in \{0,1,2\}$ define $T_v = C \cdot g^{-v}$.  If $x = v$, then $T_v = h^r$.
- The proof demonstrates that at least one $T_v$ has discrete logarithm base $h$ equal to $r$.
- **False branches** are *simulated*: pick random challenge $e_v$ and response $s_v$, then set announcement $A_v = h^{s_v} \cdot T_v^{-e_v}$.
- **Real branch** (for $x$): pick random $k$, set $A_x = h^k$.  After the Fiat–Shamir challenge $c$ is derived from the transcript, split it as $c_x = c - \sum_{v \neq x} e_v$ and respond with $s_x = k + c_x \cdot r$.

The verifier checks two equations:

1. **Challenge sum**: $e_0 + e_1 + e_2 \equiv c \pmod{2^{20}}$.
2. **Schnorr equation per branch**: $h^{s_v} \equiv A_v \cdot T_v^{e_v} \pmod p$.

If both hold, the verifier is convinced that $x \in \{0,1,2\}$ but learns nothing about which value.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         GF(3) Arithmetic                    │
│  TernaryField {0,1,2}  ──▶  add / sub / mul / inv / neg    │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌─────────────────┐    ┌─────────────┐
│ GF3Polynomial │    │ PolynomialCommit│    │ Pedersen    │
│ dense coeffs  │    │   KZG-style SRS │    │ Params      │
│ eval/add/mul  │    │ C = G^{f(τ)}    │    │ C=g^x·h^r   │
└───────────────┘    └─────────────────┘    └─────────────┘
                                                     │
                              ┌────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │    ZKProof      │
                    │  prove(x,r)     │
                    │  - simulate 2   │
                    │    false branches│
                    │  - real Schnorr │
                    │    branch for x │
                    └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   ZKVerifier    │
                    │  - challenge sum│
                    │  - Schnorr eq   │
                    │    per branch   │
                    └─────────────────┘
```

---

## Getting Started

Add to `Cargo.toml`:

```toml
[dependencies]
ternary-zkp = { path = "." }
```

```rust
use ternary_zkp::*;

fn main() {
    // 1. Choose a secret GF(3) value and randomness
    let x = 2u64; // 2 ≡ −1 mod 3
    let r = 42u64;

    // 2. Generate the non-interactive ZK proof
    let params = PedersenParams::default();
    let proof = ZKProof::prove(&params, x, r, 12345);

    // 3. Verify without learning x
    let verifier = ZKVerifier::new(params);
    assert!(verifier.verify(&proof));
    println!("ZK proof verified: x is in {{0,1,2}}");

    // 4. Polynomial commitment over GF(3)
    let pc = PolynomialCommitment::setup(7, 4);
    let f = GF3Polynomial::new(vec![TernaryField::ONE, TernaryField::NEG_ONE]);
    let c = pc.commit(&f);
    assert!(pc.verify(&f, c));
    println!("Polynomial commitment verified.");
}
```

Run it:

```bash
cargo run --example demo
```

---

## Running the Tests

The crate contains **20 tests**.  Each test isolates a single cryptographic invariant:

### Field arithmetic

| Test | What it proves |
|------|----------------|
| `test_field_add_wraps` | $2 + 1 \equiv 0$ and $1 + 1 \equiv -1$ in GF(3). |
| `test_field_sub_wraps` | Subtraction is addition of the additive inverse. |
| `test_field_mul_table` | $(-1)\cdot(-1) = 1$ and all other products respect the field axioms. |
| `test_field_inv` | Non-zero elements are self-inverting; zero has no inverse. |
| `test_field_neg_involution` | Double negation returns the original element. |
| `test_field_new_reduces` | Canonical reduction of arbitrary integers modulo 3. |

### Polynomials

| Test | What it proves |
|------|----------------|
| `test_poly_evaluate_constant` | A constant polynomial evaluates to the same value everywhere. |
| `test_poly_evaluate_linear` | $f(x)=x$ evaluates to $0,1,-1$ at the three field elements. |
| `test_poly_add_sub_roundtrip` | Adding then subtracting a polynomial recovers the original. |
| `test_poly_mul_degree` | The degree of a product equals the sum of the operand degrees. |
| `test_ternary_membership_poly_vanishes` | $x^3 - x$ is zero for every element of GF(3). |

### Commitments

| Test | What it proves |
|------|----------------|
| `test_pc_commit_verify_roundtrip` | A committed polynomial verifies against its SRS commitment. |
| `test_pc_different_polys_differ` | Distinct polynomials produce distinct commitments. |
| `test_verify_poly_commitment` | Combines coefficient-range checks with SRS verification. |

### Zero-knowledge proofs

| Test | What it proves |
|------|----------------|
| `test_zkp_verifies_x0` | The OR-proof accepts when the committed value is $0$. |
| `test_zkp_verifies_x1` | The OR-proof accepts when the committed value is $1$. |
| `test_zkp_verifies_x2` | The OR-proof accepts when the committed value is $2$. |
| `test_zkp_tampered_challenge_fails` | Modifying any challenge breaks the Fiat–Shamir sum check. |
| `test_zkp_tampered_response_fails` | Modifying any response breaks the Schnorr equation. |
| `test_zkp_check_structure` | Basic structural sanity checks pass on a valid proof. |

Execute:

```bash
cargo test
```

---

## Related crates

- [ternary-blockchain](https://github.com/SuperInstance/ternary-blockchain) — Trit-based blockchain primitives
- [ternary-secret-share](https://github.com/SuperInstance/ternary-secret-share) — Shamir sharing over $\mathbb{Z}_3$
- [ternary-field](https://github.com/SuperInstance/ternary-field) — General ternary field utilities
- [ternary-proof](https://github.com/SuperInstance/ternary-proof) — Proof systems for ternary circuits

---

## License

MIT
