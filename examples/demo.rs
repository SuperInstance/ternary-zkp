//! Runnable version of the README "Getting Started" example.
//!
//! ```bash
//! cargo run --example demo
//! ```

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
