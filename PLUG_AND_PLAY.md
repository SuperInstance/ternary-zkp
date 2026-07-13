# PLUG_AND_PLAY — ternary-zkp

> Zero-knowledge proofs over the ternary field GF(3): prove that a Pedersen
> commitment hides some `x ∈ {0,1,2}` without revealing which, plus dense
> polynomial arithmetic and an SRS polynomial commitment over GF(3).

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ternary-zkp = { git = "https://github.com/SuperInstance/ternary-zkp" }
```

Use in your code:

```rust
use ternary_zkp::*;

fn main() {
    // Secret GF(3) value (0, 1, or 2) and Pedersen randomness.
    let x = 2u64; // 2 ≡ −1 mod 3
    let r = 42u64;

    // Generate the non-interactive ZK proof that x ∈ {0,1,2}.
    let params = PedersenParams::default();
    let proof = ZKProof::prove(&params, x, r, 12345);

    // Verify without learning x.
    let verifier = ZKVerifier::new(params);
    assert!(verifier.verify(&proof));
    println!("ZK proof verified: x is in {{0,1,2}}");
}
```

The same flow is available as a runnable example:

```bash
cargo run --example demo
```

## 🧩 Core API

| Type | Use |
|------|-----|
| [`TernaryField`] | An element of GF(3): `{0, 1, 2}` where `2 ≡ −1`. Field ops `add`/`sub`/`mul`/`neg`/`inv`. |
| [`GF3Polynomial`] | Dense polynomial over GF(3): `evaluate`, `add`, `sub`, `mul`, `scale`. |
| [`PolynomialCommitment`] | KZG-style SRS commitment `C = G^{f(τ)} mod P` (`setup`, `commit`, `verify`). |
| [`PedersenParams`] | Pedersen commitment params `C = g^x · h^r mod p`. |
| [`ZKProof`] | Non-interactive CDS94 OR-proof that a commitment hides a ternary value (`prove`). |
| [`ZKVerifier`] | Verifies [`ZKProof`] transcripts (`verify`, `check_structure`). |

## ⚠️ Security note

This is **educational** code. All proof randomness comes from a
non-cryptographic LCG seeded by the `nonce` argument; **never** reuse a `nonce`
across proofs and do not rely on this crate for anything security-critical.
See the `# Security` docs on [`ZKProof::prove`] and `test_security_nonce_reuse_leaks_secret`.

## 🔗 Integration

This crate is part of the [SuperInstance ternary fleet](https://github.com/SuperInstance).

## 📄 License

MIT
