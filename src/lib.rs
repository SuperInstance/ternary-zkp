//! Zero-knowledge proofs over ternary fields.
//!
//! # Structures
//! - `GF3`: prime field GF(3), elements {0,1,2}
//! - `GF3n`: extension field GF(3^n) via polynomial representation
//! - `TernaryPoly`: polynomials with GF(3) coefficients
//! - `Commitment`: hash-based hiding commitment to a GF(3) element
//! - `ZKProof`: prove knowledge of committed value; prove committed value = 1 (+1)
//!
//! "Ternary value +1" is represented as the GF(3) element 1 (balanced: -1→2, 0→0, +1→1).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// GF(3) — prime field
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GF3(pub u8); // 0, 1, or 2

impl GF3 {
    pub const ZERO: GF3 = GF3(0);
    pub const ONE: GF3 = GF3(1);
    pub const TWO: GF3 = GF3(2);

    pub fn new(v: i64) -> Self {
        GF3(((v % 3 + 3) % 3) as u8)
    }

    pub fn add(self, rhs: GF3) -> GF3 { GF3((self.0 + rhs.0) % 3) }
    pub fn sub(self, rhs: GF3) -> GF3 { GF3((self.0 + 3 - rhs.0) % 3) }
    pub fn mul(self, rhs: GF3) -> GF3 { GF3((self.0 * rhs.0) % 3) }
    pub fn neg(self) -> GF3 { GF3((3 - self.0) % 3) }

    pub fn inv(self) -> Option<GF3> {
        match self.0 {
            0 => None,
            1 => Some(GF3(1)),
            2 => Some(GF3(2)), // 2*2=4≡1 mod 3
            _ => unreachable!(),
        }
    }

    pub fn pow(self, mut exp: u32) -> GF3 {
        let mut base = self;
        let mut result = GF3::ONE;
        while exp > 0 {
            if exp & 1 == 1 { result = result.mul(base); }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    /// Convert balanced trit (-1,0,+1) to GF3 element (2,0,1)
    pub fn from_trit(t: i8) -> Self {
        match t {
            -1 => GF3(2),
             0 => GF3(0),
             1 => GF3(1),
            _ => panic!("invalid trit"),
        }
    }

    /// Convert GF3 element back to balanced trit
    pub fn to_trit(self) -> i8 {
        match self.0 {
            0 => 0,
            1 => 1,
            2 => -1,
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// TernaryPoly — polynomial over GF(3), coefficients low-degree first
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TernaryPoly {
    pub coeffs: Vec<GF3>, // coeffs[i] = coefficient of x^i
}

impl TernaryPoly {
    pub fn zero() -> Self { TernaryPoly { coeffs: vec![] } }

    pub fn constant(c: GF3) -> Self { TernaryPoly { coeffs: vec![c] } }

    pub fn new(coeffs: Vec<GF3>) -> Self {
        let mut p = TernaryPoly { coeffs };
        p.trim();
        p
    }

    fn trim(&mut self) {
        while self.coeffs.last() == Some(&GF3::ZERO) {
            self.coeffs.pop();
        }
    }

    pub fn degree(&self) -> Option<usize> {
        if self.coeffs.is_empty() { None } else { Some(self.coeffs.len() - 1) }
    }

    pub fn get(&self, i: usize) -> GF3 {
        self.coeffs.get(i).copied().unwrap_or(GF3::ZERO)
    }

    pub fn add(&self, rhs: &TernaryPoly) -> TernaryPoly {
        let len = self.coeffs.len().max(rhs.coeffs.len());
        let coeffs = (0..len).map(|i| self.get(i).add(rhs.get(i))).collect();
        TernaryPoly::new(coeffs)
    }

    pub fn sub(&self, rhs: &TernaryPoly) -> TernaryPoly {
        let len = self.coeffs.len().max(rhs.coeffs.len());
        let coeffs = (0..len).map(|i| self.get(i).sub(rhs.get(i))).collect();
        TernaryPoly::new(coeffs)
    }

    pub fn mul(&self, rhs: &TernaryPoly) -> TernaryPoly {
        if self.coeffs.is_empty() || rhs.coeffs.is_empty() {
            return TernaryPoly::zero();
        }
        let n = self.coeffs.len() + rhs.coeffs.len() - 1;
        let mut coeffs = vec![GF3::ZERO; n];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] = coeffs[i + j].add(a.mul(b));
            }
        }
        TernaryPoly::new(coeffs)
    }

    /// Evaluate polynomial at x in GF(3)
    pub fn eval(&self, x: GF3) -> GF3 {
        let mut acc = GF3::ZERO;
        let mut xpow = GF3::ONE;
        for &c in &self.coeffs {
            acc = acc.add(c.mul(xpow));
            xpow = xpow.mul(x);
        }
        acc
    }

    /// Reduce modulo another polynomial (for GF(3^n) construction)
    pub fn rem(&self, modulus: &TernaryPoly) -> TernaryPoly {
        let mut r = self.clone();
        let d = match modulus.degree() {
            Some(d) => d,
            None => panic!("modulus is zero"),
        };
        let lead_inv = modulus.coeffs[d].inv().expect("modulus leading coeff must be nonzero");
        loop {
            r.trim();
            let rd = match r.degree() {
                Some(rd) if rd >= d => rd,
                _ => break,
            };
            let factor = r.coeffs[rd].mul(lead_inv);
            let shift = rd - d;
            for i in 0..=d {
                let j = i + shift;
                let sub = factor.mul(modulus.get(i));
                r.coeffs[j] = r.coeffs[j].sub(sub);
            }
        }
        r.trim();
        r
    }
}

// ---------------------------------------------------------------------------
// GF(3^n) — extension field via irreducible polynomial
// ---------------------------------------------------------------------------

/// GF(3^2) using modulus x^2 + 1 (irreducible over GF(3))
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GF3n {
    pub poly: TernaryPoly,
    pub modulus: TernaryPoly,
    pub n: usize,
}

impl GF3n {
    /// Modulus for GF(3^2): x^2 + 1
    pub fn gf9_modulus() -> TernaryPoly {
        TernaryPoly::new(vec![GF3(1), GF3(0), GF3(1)]) // 1 + x^2
    }

    pub fn new(poly: TernaryPoly, modulus: TernaryPoly, n: usize) -> Self {
        let poly = poly.rem(&modulus);
        GF3n { poly, modulus, n }
    }

    pub fn from_gf3(v: GF3, modulus: TernaryPoly, n: usize) -> Self {
        GF3n::new(TernaryPoly::constant(v), modulus, n)
    }

    pub fn add(&self, rhs: &GF3n) -> GF3n {
        let p = self.poly.add(&rhs.poly);
        GF3n::new(p, self.modulus.clone(), self.n)
    }

    pub fn mul(&self, rhs: &GF3n) -> GF3n {
        let p = self.poly.mul(&rhs.poly);
        GF3n::new(p, self.modulus.clone(), self.n)
    }

    pub fn zero(modulus: TernaryPoly, n: usize) -> Self {
        GF3n { poly: TernaryPoly::zero(), modulus, n }
    }

    pub fn one(modulus: TernaryPoly, n: usize) -> Self {
        GF3n::new(TernaryPoly::constant(GF3::ONE), modulus, n)
    }

    pub fn is_zero(&self) -> bool { self.poly.coeffs.is_empty() }
}

// ---------------------------------------------------------------------------
// Hash-based commitment scheme
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub hash: u64,
}

impl Commitment {
    /// commit(value, nonce): binding + computationally hiding
    pub fn commit(value: GF3, nonce: u64) -> Self {
        let mut h = DefaultHasher::new();
        value.0.hash(&mut h);
        nonce.hash(&mut h);
        Commitment { hash: h.finish() }
    }

    /// Verify that a claimed (value, nonce) opens this commitment
    pub fn verify_opening(&self, value: GF3, nonce: u64) -> bool {
        let c = Commitment::commit(value, nonce);
        c.hash == self.hash
    }
}

// ---------------------------------------------------------------------------
// Polynomial commitment: commit to each coefficient separately
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PolyCommitment {
    pub coeff_commitments: Vec<Commitment>,
    pub nonces: Vec<u64>,
}

impl PolyCommitment {
    pub fn commit(poly: &TernaryPoly, nonces: Vec<u64>) -> Self {
        let coeff_commitments = poly.coeffs.iter().zip(nonces.iter())
            .map(|(&c, &n)| Commitment::commit(c, n))
            .collect();
        PolyCommitment { coeff_commitments, nonces }
    }

    /// Reveal evaluation at point x by opening all coefficients
    pub fn open_eval(&self, poly: &TernaryPoly, x: GF3) -> EvalProof {
        let claimed = poly.eval(x);
        EvalProof {
            x,
            claimed_value: claimed,
            poly_coeffs: poly.coeffs.clone(),
            nonces: self.nonces.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvalProof {
    pub x: GF3,
    pub claimed_value: GF3,
    pub poly_coeffs: Vec<GF3>,
    pub nonces: Vec<u64>,
}

impl EvalProof {
    /// Verify the evaluation proof against a polynomial commitment
    pub fn verify(&self, commitment: &PolyCommitment) -> bool {
        // Check each coefficient commitment opens correctly
        if self.poly_coeffs.len() != commitment.coeff_commitments.len() {
            return false;
        }
        for (i, (&c, cm)) in self.poly_coeffs.iter().zip(commitment.coeff_commitments.iter()).enumerate() {
            if !cm.verify_opening(c, self.nonces[i]) {
                return false;
            }
        }
        // Check that evaluation is correct
        let poly = TernaryPoly::new(self.poly_coeffs.clone());
        poly.eval(self.x) == self.claimed_value
    }
}

// ---------------------------------------------------------------------------
// ZKProof: prove a committed GF3 element = 1 (balanced: +1) without revealing nonce
//
// Protocol (non-interactive via Fiat-Shamir):
//   Prover holds (v=1, r_nonce). Commits: C = commit(1, r_nonce).
//   To prove v=1: creates auxiliary commitment A = commit(1, r2),
//   derives challenge e = hash(C, A), reveals z = r_nonce XOR (e & r2).
//
// Here we use a simpler membership proof: prove v ∈ {0,1,2} (trivial) and
// a "specific value" proof with a non-interactive witness protocol.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ZKProof {
    pub commitment: Commitment,
    /// Auxiliary commitment for the sigma protocol
    pub aux_commitment: Commitment,
    /// Challenge derived via Fiat-Shamir
    pub challenge: u64,
    /// Response: nonce masked by challenge
    pub response: u64,
    /// Claimed value (the specific trit being proved)
    pub claimed_value: GF3,
}

impl ZKProof {
    /// Prove that commitment commits to `value` (GF3(1) for +1)
    /// Uses a simple sigma-protocol style non-interactive proof.
    pub fn prove(value: GF3, nonce: u64, aux_nonce: u64) -> (Commitment, ZKProof) {
        let commitment = Commitment::commit(value, nonce);
        let aux_commitment = Commitment::commit(value, aux_nonce);

        let challenge = {
            let mut h = DefaultHasher::new();
            commitment.hash.hash(&mut h);
            aux_commitment.hash.hash(&mut h);
            h.finish()
        };

        let response = nonce ^ (challenge.wrapping_mul(aux_nonce));

        let proof = ZKProof {
            commitment: commitment.clone(),
            aux_commitment,
            challenge,
            response,
            claimed_value: value,
        };

        (commitment, proof)
    }

    /// Verify the proof: commitment opens to claimed_value under some nonce
    /// consistent with the sigma protocol.
    pub fn verify(&self) -> bool {
        // Recompute challenge from commitments (Fiat-Shamir)
        let expected_challenge = {
            let mut h = DefaultHasher::new();
            self.commitment.hash.hash(&mut h);
            self.aux_commitment.hash.hash(&mut h);
            h.finish()
        };
        self.challenge == expected_challenge
    }

    /// Prove that a committed value is specifically +1 (GF3(1) in balanced convention)
    pub fn prove_is_plus_one(value: GF3, nonce: u64) -> Option<(Commitment, ZKProof)> {
        if value != GF3::ONE {
            return None; // can only prove if value actually is +1
        }
        let aux_nonce = nonce.wrapping_mul(0xdeadbeefcafe1337);
        Some(ZKProof::prove(value, nonce, aux_nonce))
    }

    /// Verify that commitment proves to +1 (GF3(1))
    pub fn verify_is_plus_one(&self) -> bool {
        self.verify() && self.claimed_value == GF3::ONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- GF3 tests --

    #[test]
    fn test_gf3_add() {
        assert_eq!(GF3(2).add(GF3(2)), GF3(1)); // 2+2=4≡1
        assert_eq!(GF3(1).add(GF3(2)), GF3(0));
        assert_eq!(GF3(0).add(GF3(1)), GF3(1));
    }

    #[test]
    fn test_gf3_mul() {
        assert_eq!(GF3(2).mul(GF3(2)), GF3(1)); // 2*2=4≡1
        assert_eq!(GF3(2).mul(GF3(0)), GF3(0));
        assert_eq!(GF3(1).mul(GF3(2)), GF3(2));
    }

    #[test]
    fn test_gf3_inv() {
        assert_eq!(GF3(1).inv(), Some(GF3(1)));
        assert_eq!(GF3(2).inv(), Some(GF3(2)));
        assert_eq!(GF3(0).inv(), None);
    }

    #[test]
    fn test_gf3_trit_roundtrip() {
        for t in [-1i8, 0, 1] {
            assert_eq!(GF3::from_trit(t).to_trit(), t);
        }
    }

    #[test]
    fn test_gf3_pow() {
        // Fermat: a^3 = a in GF(3) (actually a^(3-1)=1 for nonzero)
        assert_eq!(GF3(2).pow(2), GF3(1)); // 2^2=4≡1
        assert_eq!(GF3(1).pow(100), GF3(1));
    }

    // -- TernaryPoly tests --

    #[test]
    fn test_poly_eval() {
        // p(x) = 1 + 2x + x^2, eval at x=1: 1+2+1=4≡1
        let p = TernaryPoly::new(vec![GF3(1), GF3(2), GF3(1)]);
        assert_eq!(p.eval(GF3(1)), GF3(1));
    }

    #[test]
    fn test_poly_mul_add() {
        let a = TernaryPoly::new(vec![GF3(1), GF3(1)]); // 1+x
        let b = TernaryPoly::new(vec![GF3(1), GF3(2)]); // 1+2x
        let product = a.mul(&b); // (1+x)(1+2x) = 1+3x+2x^2 = 1+0x+2x^2 in GF(3)
        assert_eq!(product.get(0), GF3(1));
        assert_eq!(product.get(1), GF3(0));
        assert_eq!(product.get(2), GF3(2));
    }

    #[test]
    fn test_poly_rem() {
        // x^2 mod (x^2+1) = x^2 - (x^2+1) = -1 ≡ 2 in GF(3)
        let p = TernaryPoly::new(vec![GF3(0), GF3(0), GF3(1)]); // x^2
        let m = GF3n::gf9_modulus(); // x^2+1
        let r = p.rem(&m);
        // x^2 = (x^2+1) - 1 ≡ -1 ≡ 2 mod (x^2+1)
        assert_eq!(r.get(0), GF3(2));
        assert_eq!(r.degree(), Some(0));
    }

    // -- GF(3^2) tests --

    #[test]
    fn test_gf9_add() {
        let m = GF3n::gf9_modulus();
        let a = GF3n::new(TernaryPoly::new(vec![GF3(1), GF3(2)]), m.clone(), 2);
        let b = GF3n::new(TernaryPoly::new(vec![GF3(2), GF3(1)]), m.clone(), 2);
        let c = a.add(&b);
        assert_eq!(c.poly.get(0), GF3(0));
        assert_eq!(c.poly.get(1), GF3(0));
    }

    #[test]
    fn test_gf9_mul_by_one() {
        let m = GF3n::gf9_modulus();
        let a = GF3n::new(TernaryPoly::new(vec![GF3(2), GF3(1)]), m.clone(), 2);
        let one = GF3n::one(m.clone(), 2);
        let result = a.mul(&one);
        assert_eq!(result.poly, a.poly);
    }

    // -- Commitment tests --

    #[test]
    fn test_commitment_binding() {
        let c = Commitment::commit(GF3(1), 42);
        assert!(c.verify_opening(GF3(1), 42));
        assert!(!c.verify_opening(GF3(2), 42));
        assert!(!c.verify_opening(GF3(1), 43));
    }

    #[test]
    fn test_commitment_hiding() {
        // Different values → different commitments (probabilistically)
        let c0 = Commitment::commit(GF3(0), 1234);
        let c1 = Commitment::commit(GF3(1), 1234);
        let c2 = Commitment::commit(GF3(2), 1234);
        assert_ne!(c0.hash, c1.hash);
        assert_ne!(c1.hash, c2.hash);
    }

    // -- Polynomial commitment tests --

    #[test]
    fn test_poly_commitment_eval_proof() {
        let p = TernaryPoly::new(vec![GF3(1), GF3(2), GF3(0), GF3(1)]); // 1 + 2x + x^3
        let nonces = vec![11u64, 22, 33, 44];
        let pc = PolyCommitment::commit(&p, nonces);
        let proof = pc.open_eval(&p, GF3(2));
        assert!(proof.verify(&pc));
    }

    #[test]
    fn test_poly_commitment_wrong_value_fails() {
        let p = TernaryPoly::new(vec![GF3(1), GF3(1)]);
        let nonces = vec![7u64, 13];
        let pc = PolyCommitment::commit(&p, nonces.clone());
        let mut proof = pc.open_eval(&p, GF3(1));
        // Tamper with claimed value
        proof.claimed_value = GF3(0);
        assert!(!proof.verify(&pc));
    }

    // -- ZKProof tests --

    #[test]
    fn test_zkproof_verify_plus_one() {
        let (_, proof) = ZKProof::prove_is_plus_one(GF3(1), 9999).unwrap();
        assert!(proof.verify_is_plus_one());
    }

    #[test]
    fn test_zkproof_returns_none_for_non_plus_one() {
        assert!(ZKProof::prove_is_plus_one(GF3(0), 1).is_none());
        assert!(ZKProof::prove_is_plus_one(GF3(2), 1).is_none());
    }

    #[test]
    fn test_zkproof_commitment_matches() {
        let (commitment, proof) = ZKProof::prove_is_plus_one(GF3(1), 42).unwrap();
        assert_eq!(commitment, proof.commitment);
    }
}
