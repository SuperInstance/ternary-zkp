//! Zero-knowledge proofs over the ternary field GF(3).
//!
//! - [`TernaryField`]        GF(3) arithmetic; elements {0,1,2}, where 2 ≡ −1
//! - [`GF3Polynomial`]       dense polynomials over GF(3)
//! - [`PolynomialCommitment`] SRS-based commit: C(f) = g^{f(τ)} mod p
//! - [`ZKProof`]             CDS94 OR-proof that a Pedersen commitment hides
//!                           some x ∈ {0,1,2} without revealing which
//! - [`ZKVerifier`]          verifies ZKProof transcripts

// ─── modular arithmetic ───────────────────────────────────────────────────────

/// Fast modular exponentiation.
pub fn modpow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

/// Modular inverse via Fermat's little theorem (prime modulus required).
pub fn modinv(a: u64, p: u64) -> u64 {
    modpow(a, p - 2, p)
}

/// Fiat-Shamir challenge hash — deterministic, domain-separated LCG mix.
pub fn challenge_hash(values: &[u64]) -> u64 {
    let mut h: u64 = 0xdead_beef_cafe_babe;
    for &v in values {
        h = h
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(v.wrapping_add(1))
            .wrapping_add(1_442_695_040_888_963_407);
    }
    // 20-bit result in [1, 2^20]
    (h >> 8) % (1 << 20) + 1
}

fn prng(seed: u64) -> u64 {
    seed.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

const P: u64 = 1_000_000_007; // prime modulus
const G: u64 = 2; // generator for commitment scheme
const H: u64 = 3; // independent second generator for Pedersen
const CHAL_MOD: u64 = 1 << 20; // challenge space

// ─── TernaryField ─────────────────────────────────────────────────────────────

/// An element of GF(3): stored as 0, 1, or 2 (where 2 ≡ −1 mod 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TernaryField(pub u8);

impl TernaryField {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const NEG_ONE: Self = Self(2); // −1 ≡ 2 mod 3

    /// Construct from any integer, canonically reducing mod 3.
    pub fn new(v: i64) -> Self {
        Self(((v % 3 + 3) % 3) as u8)
    }

    pub fn add(self, rhs: Self) -> Self {
        Self((self.0 + rhs.0) % 3)
    }
    pub fn sub(self, rhs: Self) -> Self {
        Self((self.0 + 3 - rhs.0) % 3)
    }
    pub fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0 % 3)
    }
    pub fn neg(self) -> Self {
        Self((3 - self.0) % 3)
    }

    /// Multiplicative inverse; `None` for zero (not invertible).
    pub fn inv(self) -> Option<Self> {
        match self.0 {
            0 => None,
            1 => Some(Self(1)),
            2 => Some(Self(2)), // 2 × 2 = 4 ≡ 1 mod 3
            _ => unreachable!(),
        }
    }

    pub fn pow(self, exp: u32) -> Self {
        let mut result = Self::ONE;
        for _ in 0..exp {
            result = result.mul(self);
        }
        result
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Signed integer view: 0 → 0, 1 → +1, 2 → −1.
    pub fn to_i8(self) -> i8 {
        match self.0 {
            0 => 0,
            1 => 1,
            _ => -1,
        }
    }
}

// ─── GF3Polynomial ────────────────────────────────────────────────────────────

/// Dense polynomial over GF(3).  `coeffs[i]` is the coefficient of xⁱ.
#[derive(Debug, Clone, PartialEq)]
pub struct GF3Polynomial {
    pub coeffs: Vec<TernaryField>,
}

impl GF3Polynomial {
    pub fn new(coeffs: Vec<TernaryField>) -> Self {
        let mut p = Self { coeffs };
        p.trim();
        p
    }

    pub fn zero() -> Self {
        Self { coeffs: vec![] }
    }

    pub fn constant(c: TernaryField) -> Self {
        if c.is_zero() {
            Self::zero()
        } else {
            Self::new(vec![c])
        }
    }

    fn trim(&mut self) {
        while self.coeffs.last() == Some(&TernaryField::ZERO) {
            self.coeffs.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty()
    }

    pub fn degree(&self) -> Option<usize> {
        if self.coeffs.is_empty() {
            None
        } else {
            Some(self.coeffs.len() - 1)
        }
    }

    fn coeff(&self, i: usize) -> TernaryField {
        self.coeffs.get(i).copied().unwrap_or(TernaryField::ZERO)
    }

    pub fn evaluate(&self, x: TernaryField) -> TernaryField {
        let mut result = TernaryField::ZERO;
        let mut power = TernaryField::ONE;
        for &c in &self.coeffs {
            result = result.add(c.mul(power));
            power = power.mul(x);
        }
        result
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let n = self.coeffs.len().max(rhs.coeffs.len());
        Self::new((0..n).map(|i| self.coeff(i).add(rhs.coeff(i))).collect())
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let n = self.coeffs.len().max(rhs.coeffs.len());
        Self::new((0..n).map(|i| self.coeff(i).sub(rhs.coeff(i))).collect())
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();
        }
        let n = self.coeffs.len() + rhs.coeffs.len() - 1;
        let mut coeffs = vec![TernaryField::ZERO; n];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] = coeffs[i + j].add(a.mul(b));
            }
        }
        Self::new(coeffs)
    }

    pub fn scale(&self, s: TernaryField) -> Self {
        Self::new(self.coeffs.iter().map(|&c| c.mul(s)).collect())
    }

    /// x³ − x: vanishes on every element of GF(3) (Fermat's little theorem).
    pub fn ternary_membership_poly() -> Self {
        // coeffs [0, 2, 0, 1] → 2x + x³ (and 2 ≡ −1, so this is x³ − x)
        Self::new(vec![
            TernaryField::ZERO,
            TernaryField::NEG_ONE,
            TernaryField::ZERO,
            TernaryField::ONE,
        ])
    }
}

// ─── PolynomialCommitment ─────────────────────────────────────────────────────

/// KZG-style SRS commitment to a polynomial over GF(3).
///
/// Setup chooses a secret τ; `srs[i] = G^{τⁱ} mod P`.
/// `commit(f) = ∏ srs[i]^{fᵢ} = G^{f(τ)} mod P`.
#[derive(Debug, Clone)]
pub struct PolynomialCommitment {
    pub srs: Vec<u64>,
}

impl PolynomialCommitment {
    pub fn setup(tau: u64, max_degree: usize) -> Self {
        let ord = P - 1;
        let mut srs = vec![1u64; max_degree + 1];
        let mut exp = 1u64;
        for s in srs.iter_mut() {
            *s = modpow(G, exp, P);
            exp = exp * tau % ord;
        }
        Self { srs }
    }

    pub fn commit(&self, poly: &GF3Polynomial) -> u64 {
        let mut c = 1u64;
        for (i, &coeff) in poly.coeffs.iter().enumerate() {
            if i >= self.srs.len() {
                break;
            }
            c = c * modpow(self.srs[i], coeff.0 as u64, P) % P;
        }
        c
    }

    pub fn verify(&self, poly: &GF3Polynomial, commitment: u64) -> bool {
        self.commit(poly) == commitment
    }
}

// ─── ZKProof ──────────────────────────────────────────────────────────────────

/// Parameters for a Pedersen commitment C = g^x · h^r mod p.
#[derive(Debug, Clone)]
pub struct PedersenParams {
    pub g: u64,
    pub h: u64,
    pub p: u64,
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self { g: G, h: H, p: P }
    }
}

impl PedersenParams {
    pub fn commit(&self, x: u64, r: u64) -> u64 {
        modpow(self.g, x, self.p) * modpow(self.h, r, self.p) % self.p
    }
}

/// Non-interactive OR-composition Schnorr proof (Fiat-Shamir heuristic).
///
/// Proves that Pedersen commitment C = g^x · h^r hides some x ∈ {0,1,2}
/// (i.e., x is a valid GF(3) / ternary value) without revealing which.
///
/// For each branch v ∈ {0,1,2}, define T_v = C · g^{−v}.
/// If x = v then T_v = h^r.  The proof demonstrates ∃ v: DL_h(T_v) = r.
///
/// False branches are simulated: pick (e_v, s_v), set A_v = h^{s_v} · T_v^{−e_v}.
/// Real branch: A_x = h^k, then after Fiat-Shamir c_x = c − Σe_v, s_x = k + c_x·r.
#[derive(Debug, Clone)]
pub struct ZKProof {
    pub commitment: u64,
    pub announcements: [u64; 3],
    pub challenges: [u64; 3],
    pub responses: [u64; 3],
}

impl ZKProof {
    /// Prove that `x ∈ {0,1,2}` is committed in C = g^x · h^r.
    ///
    /// `nonce` is deterministic randomness; use fresh secure entropy in production.
    pub fn prove(params: &PedersenParams, x: u64, r: u64, nonce: u64) -> Self {
        assert!(x < 3, "x must be in {{0,1,2}}");
        let (p, h, ord) = (params.p, params.h, params.p - 1);
        let commitment = params.commit(x, r);

        // T_v = C · g^{−v} mod p
        let tv = |v: u64| -> u64 {
            let g_neg_v = if v == 0 {
                1u64
            } else {
                modpow(params.g, ord - v, p)
            };
            commitment * g_neg_v % p
        };

        let mut announcements = [0u64; 3];
        let mut challenges = [0u64; 3];
        let mut responses = [0u64; 3];

        // Simulate false branches
        let mut seed = prng(nonce.wrapping_add(0xcafe));
        for v in 0..3u64 {
            if v == x {
                continue;
            }
            let e_v = prng(seed) % CHAL_MOD + 1;
            seed = prng(seed);
            let s_v = prng(seed) % ord + 1;
            seed = prng(seed);
            challenges[v as usize] = e_v;
            responses[v as usize] = s_v;
            // A_v = h^{s_v} · T_v^{−e_v}
            announcements[v as usize] =
                modpow(h, s_v, p) * modpow(modinv(tv(v), p), e_v, p) % p;
        }

        // Real branch announcement: A_x = h^k
        let k = prng(seed) % ord + 1;
        announcements[x as usize] = modpow(h, k, p);

        // Fiat-Shamir global challenge
        let global_c = challenge_hash(&[
            commitment,
            announcements[0],
            announcements[1],
            announcements[2],
        ]);

        // Split: c_x = global_c − Σ_{v≠x} e_v  (mod CHAL_MOD)
        let sum_false: u64 = (0..3u64)
            .filter(|&v| v != x)
            .map(|v| challenges[v as usize])
            .sum();
        challenges[x as usize] =
            (global_c + CHAL_MOD * 4 - sum_false % CHAL_MOD) % CHAL_MOD;
        let c_x = challenges[x as usize];

        // Real response: s_x = k + c_x · r  (mod ord)
        responses[x as usize] = (k + c_x * r) % ord;

        Self {
            commitment,
            announcements,
            challenges,
            responses,
        }
    }
}

// ─── ZKVerifier ───────────────────────────────────────────────────────────────

/// Verifies [`ZKProof`] transcripts produced by [`ZKProof::prove`].
pub struct ZKVerifier {
    pub params: PedersenParams,
}

impl ZKVerifier {
    pub fn new(params: PedersenParams) -> Self {
        Self { params }
    }

    /// Full verification:
    ///  1. Commitment is in range (1..p).
    ///  2. Challenges sum to recomputed Fiat-Shamir value (mod CHAL_MOD).
    ///  3. Schnorr equation holds for every branch: h^{s_v} = A_v · T_v^{c_v}.
    pub fn verify(&self, proof: &ZKProof) -> bool {
        let (p, h, ord) = (self.params.p, self.params.h, self.params.p - 1);
        let c = proof.commitment;

        if c == 0 || c >= p {
            return false;
        }

        let tv = |v: u64| -> u64 {
            let g_neg_v = if v == 0 {
                1u64
            } else {
                modpow(self.params.g, ord - v, p)
            };
            c * g_neg_v % p
        };

        // 1. Challenge sum
        let global_c = challenge_hash(&[
            c,
            proof.announcements[0],
            proof.announcements[1],
            proof.announcements[2],
        ]);
        let sum_c = proof.challenges.iter().sum::<u64>() % CHAL_MOD;
        if sum_c != global_c % CHAL_MOD {
            return false;
        }

        // 2. Schnorr equation for each branch: h^{s_v} == A_v · T_v^{c_v}
        for v in 0..3u64 {
            let lhs = modpow(h, proof.responses[v as usize], p);
            let rhs = proof.announcements[v as usize]
                * modpow(tv(v), proof.challenges[v as usize], p)
                % p;
            if lhs != rhs {
                return false;
            }
        }

        true
    }

    /// Sanity check: commitment in range, at least one non-zero challenge.
    pub fn check_structure(&self, proof: &ZKProof) -> bool {
        proof.commitment > 0
            && proof.commitment < self.params.p
            && proof.challenges.iter().any(|&c| c > 0)
    }

    /// Verify a polynomial's GF(3) range and its SRS commitment in one call.
    pub fn verify_poly_commitment(
        &self,
        pc: &PolynomialCommitment,
        poly: &GF3Polynomial,
        commitment: u64,
    ) -> bool {
        poly.coeffs.iter().all(|c| c.0 < 3) && pc.verify(poly, commitment)
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TernaryField ──────────────────────────────────────────────────────────

    #[test]
    fn test_field_add_wraps() {
        // 2 + 1 = 3 ≡ 0;  1 + 1 = 2 ≡ −1
        assert_eq!(TernaryField(2).add(TernaryField(1)), TernaryField::ZERO);
        assert_eq!(TernaryField(1).add(TernaryField(1)), TernaryField::NEG_ONE);
    }

    #[test]
    fn test_field_sub_wraps() {
        assert_eq!(TernaryField::ZERO.sub(TernaryField::ONE), TernaryField::NEG_ONE);
        assert_eq!(TernaryField::ONE.sub(TernaryField::NEG_ONE), TernaryField::NEG_ONE);
    }

    #[test]
    fn test_field_mul_table() {
        assert_eq!(TernaryField::NEG_ONE.mul(TernaryField::NEG_ONE), TernaryField::ONE);
        assert_eq!(TernaryField::ZERO.mul(TernaryField::ONE), TernaryField::ZERO);
        assert_eq!(TernaryField::ONE.mul(TernaryField::NEG_ONE), TernaryField::NEG_ONE);
    }

    #[test]
    fn test_field_inv() {
        assert_eq!(TernaryField::ONE.inv(), Some(TernaryField::ONE));
        assert_eq!(TernaryField::NEG_ONE.inv(), Some(TernaryField::NEG_ONE));
        assert_eq!(TernaryField::ZERO.inv(), None);
    }

    #[test]
    fn test_field_neg_involution() {
        for v in 0u8..3 {
            let x = TernaryField(v);
            assert_eq!(x.neg().neg(), x);
        }
    }

    #[test]
    fn test_field_new_reduces() {
        assert_eq!(TernaryField::new(-1), TernaryField::NEG_ONE);
        assert_eq!(TernaryField::new(4), TernaryField::ONE);
        assert_eq!(TernaryField::new(9), TernaryField::ZERO);
    }

    // ── GF3Polynomial ─────────────────────────────────────────────────────────

    #[test]
    fn test_poly_evaluate_constant() {
        let p = GF3Polynomial::constant(TernaryField::ONE);
        for v in 0u8..3 {
            assert_eq!(p.evaluate(TernaryField(v)), TernaryField::ONE);
        }
    }

    #[test]
    fn test_poly_evaluate_linear() {
        // f(x) = x: f(0)=0, f(1)=1, f(2)=2≡−1
        let f = GF3Polynomial::new(vec![TernaryField::ZERO, TernaryField::ONE]);
        assert_eq!(f.evaluate(TernaryField(0)), TernaryField::ZERO);
        assert_eq!(f.evaluate(TernaryField(1)), TernaryField::ONE);
        assert_eq!(f.evaluate(TernaryField(2)), TernaryField::NEG_ONE);
    }

    #[test]
    fn test_poly_add_sub_roundtrip() {
        let f = GF3Polynomial::new(vec![TernaryField::ONE, TernaryField::NEG_ONE]);
        let g = GF3Polynomial::new(vec![TernaryField::NEG_ONE, TernaryField::ONE]);
        assert_eq!(f.add(&g).sub(&g), f);
    }

    #[test]
    fn test_poly_mul_degree() {
        // x · (x+1) has degree 2
        let x = GF3Polynomial::new(vec![TernaryField::ZERO, TernaryField::ONE]);
        let x1 = GF3Polynomial::new(vec![TernaryField::ONE, TernaryField::ONE]);
        assert_eq!(x.mul(&x1).degree(), Some(2));
    }

    #[test]
    fn test_ternary_membership_poly_vanishes() {
        // x³ − x must be 0 for all x ∈ GF(3)
        let p = GF3Polynomial::ternary_membership_poly();
        for v in 0u8..3 {
            assert_eq!(
                p.evaluate(TernaryField(v)),
                TernaryField::ZERO,
                "x³−x should vanish at {}",
                v
            );
        }
    }

    // ── PolynomialCommitment ───────────────────────────────────────────────────

    #[test]
    fn test_pc_commit_verify_roundtrip() {
        let pc = PolynomialCommitment::setup(7, 4);
        let f = GF3Polynomial::new(vec![
            TernaryField::ONE,
            TernaryField::NEG_ONE,
            TernaryField::ONE,
        ]);
        let c = pc.commit(&f);
        assert!(pc.verify(&f, c));
    }

    #[test]
    fn test_pc_different_polys_differ() {
        let pc = PolynomialCommitment::setup(13, 4);
        let f = GF3Polynomial::new(vec![TernaryField::ONE, TernaryField::NEG_ONE]);
        let g = GF3Polynomial::new(vec![TernaryField::NEG_ONE, TernaryField::ONE]);
        assert_ne!(pc.commit(&f), pc.commit(&g));
    }

    // ── ZKProof / ZKVerifier ──────────────────────────────────────────────────

    #[test]
    fn test_zkp_verifies_x0() {
        let params = PedersenParams::default();
        let proof = ZKProof::prove(&params, 0, 42, 1);
        assert!(ZKVerifier::new(params).verify(&proof));
    }

    #[test]
    fn test_zkp_verifies_x1() {
        let params = PedersenParams::default();
        let proof = ZKProof::prove(&params, 1, 100, 999);
        assert!(ZKVerifier::new(params).verify(&proof));
    }

    #[test]
    fn test_zkp_verifies_x2() {
        let params = PedersenParams::default();
        let proof = ZKProof::prove(&params, 2, 77, 12345);
        assert!(ZKVerifier::new(params).verify(&proof));
    }

    #[test]
    fn test_zkp_tampered_challenge_fails() {
        let params = PedersenParams::default();
        let mut proof = ZKProof::prove(&params, 1, 50, 7);
        proof.challenges[0] = proof.challenges[0].wrapping_add(1);
        assert!(!ZKVerifier::new(params).verify(&proof));
    }

    #[test]
    fn test_zkp_tampered_response_fails() {
        let params = PedersenParams::default();
        let mut proof = ZKProof::prove(&params, 0, 33, 3);
        proof.responses[0] = proof.responses[0].wrapping_add(1) % (P - 1);
        assert!(!ZKVerifier::new(params).verify(&proof));
    }

    #[test]
    fn test_zkp_check_structure() {
        let params = PedersenParams::default();
        let proof = ZKProof::prove(&params, 2, 88, 404);
        assert!(ZKVerifier::new(params.clone()).check_structure(&proof));
    }

    #[test]
    fn test_verify_poly_commitment() {
        let params = PedersenParams::default();
        let v = ZKVerifier::new(params);
        let pc = PolynomialCommitment::setup(11, 3);
        let poly = GF3Polynomial::new(vec![TernaryField::ONE, TernaryField::NEG_ONE]);
        let c = pc.commit(&poly);
        assert!(v.verify_poly_commitment(&pc, &poly, c));
    }
}
