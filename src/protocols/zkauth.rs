//! ZK Authentication: EdDSA on JubJub with Poseidon + Ckt_auth circuit.
//!
//! This module provides:
//! - Native EdDSA (KeyGen, Sign, Verify) on JubJub using Poseidon
//! - ZK-friendly token issuance and verification
//! - The Ckt_auth R1CS circuit (~6,001 constraints)
//!
//! Simplified vs zkLogin: no ephemeral key (vk_u, sk_u, σ_u) needed.
//! Per-email binding is provided by C (unique per email) as a public input.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::EdwardsAffine as JubJubAffine;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_r1cs_std::ToBitsGadget;
use rand::Rng;

use crate::protocols::hash_to_prime::snark_hash::poseidon_config_for_test;

// ============================================================
// Native EdDSA on JubJub
// ============================================================

/// EdDSA keypair on JubJub.
#[derive(Clone, Debug)]
pub struct EdDSAKeyPair {
    pub sk: Fr,
    pub pk: JubJubAffine,
}

/// EdDSA signature: (R, s) where R is a curve point, s is a scalar.
#[derive(Clone, Debug)]
pub struct EdDSASignature {
    pub r_point: JubJubAffine,
    pub s: Fr,
}

/// ZK-friendly identity token (no ephemeral key).
#[derive(Clone, Debug)]
pub struct ZkToken {
    pub sub: Fr,
    pub iss: Fr,
    pub t_exp: Fr,
    pub sigma: EdDSASignature,
}

/// Generate an EdDSA keypair on JubJub.
pub fn eddsa_keygen<R: Rng>(rng: &mut R) -> EdDSAKeyPair {
    let sk = Fr::rand(rng);
    let gen = JubJubAffine::generator();
    let pk = gen.mul_bigint(sk.into_bigint()).into_affine();
    EdDSAKeyPair { sk, pk }
}

/// Compute Poseidon challenge for EdDSA: e = Poseidon(R_x, R_y, pk_x, pk_y, m)
fn eddsa_challenge(
    config: &PoseidonConfig<Fr>,
    r_point: &JubJubAffine,
    pk: &JubJubAffine,
    message: &Fr,
) -> Fr {
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&r_point.x);
    sponge.absorb(&r_point.y);
    sponge.absorb(&pk.x);
    sponge.absorb(&pk.y);
    sponge.absorb(message);
    sponge.squeeze_field_elements(1)[0]
}

/// Sign a message with EdDSA on JubJub using Poseidon.
/// Scalar arithmetic in JubJub scalar field (order ℓ), not BLS12-381 Fr (order r).
pub fn eddsa_sign<R: Rng>(
    rng: &mut R,
    sk: &Fr,
    pk: &JubJubAffine,
    message: &Fr,
) -> EdDSASignature {
    use ark_ed_on_bls12_381::Fr as JubJubFr;
    let config = poseidon_config_for_test::<Fr>();
    let gen = JubJubAffine::generator();

    let k_jj = JubJubFr::rand(rng);
    let r_point = gen.mul_bigint(k_jj.into_bigint()).into_affine();

    let e_bls = eddsa_challenge(&config, &r_point, pk, message);

    let e_jj = JubJubFr::from_le_bytes_mod_order(
        &e_bls.into_bigint().to_bytes_le()
    );

    let sk_jj = JubJubFr::from_le_bytes_mod_order(
        &sk.into_bigint().to_bytes_le()
    );

    let s_jj = k_jj + e_jj * sk_jj;

    let s = Fr::from_le_bytes_mod_order(
        &s_jj.into_bigint().to_bytes_le()
    );

    EdDSASignature { r_point, s }
}

/// Verify an EdDSA signature: check [s]·B == R + [e]·pk
pub fn eddsa_verify(
    pk: &JubJubAffine,
    signature: &EdDSASignature,
    message: &Fr,
) -> bool {
    let config = poseidon_config_for_test::<Fr>();
    let gen = JubJubAffine::generator();

    let e = eddsa_challenge(&config, &signature.r_point, pk, message);

    let lhs = gen.mul_bigint(signature.s.into_bigint());
    let rhs = signature.r_point.into_group()
        + pk.mul_bigint(e.into_bigint());

    lhs == rhs
}

// ============================================================
// ZK Token operations (no ephemeral key)
// ============================================================

/// Compute token hash: h_τ = Poseidon(sub, iss, t_exp)
pub fn compute_token_hash(sub: &Fr, iss: &Fr, t_exp: &Fr) -> Fr {
    let config = poseidon_config_for_test::<Fr>();
    let mut sponge = PoseidonSponge::new(&config);
    sponge.absorb(sub);
    sponge.absorb(iss);
    sponge.absorb(t_exp);
    sponge.squeeze_field_elements(1)[0]
}

/// Compute issuer field element: iss = Poseidon(domain_bytes)
pub fn compute_iss(domain: &str) -> Fr {
    let config = poseidon_config_for_test::<Fr>();
    let mut sponge = PoseidonSponge::new(&config);
    for &b in domain.as_bytes() {
        sponge.absorb(&Fr::from(b as u64));
    }
    sponge.absorb(&Fr::from(888888u64));
    sponge.squeeze_field_elements(1)[0]
}

/// Pack email bytes into a field element: sub = Σ b_i · 256^i
pub fn pack_email_to_field(email: &str) -> Fr {
    let bytes = email.as_bytes();
    assert!(bytes.len() <= 31, "Email too long ({} bytes, max 31)", bytes.len());
    let mut result = Fr::from(0u64);
    let mut power = Fr::from(1u64);
    for i in 0..31usize {
        let byte_val = if i < bytes.len() {
            Fr::from(bytes[i] as u64)
        } else {
            Fr::from(0u64)
        };
        result += byte_val * power;
        power *= Fr::from(256u64);
    }
    result
}

/// Issue a ZK-friendly token.
pub fn token_issue<R: Rng>(
    rng: &mut R,
    sk_op: &Fr,
    pk_op: &JubJubAffine,
    sub: &Fr,
    iss: &Fr,
    t_exp: &Fr,
) -> ZkToken {
    let h_tau = compute_token_hash(sub, iss, t_exp);
    let sigma = eddsa_sign(rng, sk_op, pk_op, &h_tau);
    ZkToken {
        sub: *sub,
        iss: *iss,
        t_exp: *t_exp,
        sigma,
    }
}

/// Verify a ZK-friendly token.
pub fn token_verify(pk_op: &JubJubAffine, token: &ZkToken) -> bool {
    let h_tau = compute_token_hash(&token.sub, &token.iss, &token.t_exp);
    eddsa_verify(pk_op, &token.sigma, &h_tau)
}

// ============================================================
// Ckt_auth: R1CS Circuit Definition (no ephemeral key)
// ============================================================

use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Public inputs for Ckt_auth (no vk_u).
#[derive(Clone)]
pub struct AuthPublicInputs {
    pub pk_op_x: Fr,
    pub pk_op_y: Fr,
    pub iss: Fr,
    pub t_exp: Fr,
    pub ciphertext_c: Fr,
}

/// Private witnesses for Ckt_auth.
#[derive(Clone)]
pub struct AuthPrivateWitnesses {
    pub sub: Fr,
    pub r_x: Fr,
    pub r_y: Fr,
    pub s: Fr,
    pub k: Fr,
}

/// The authentication circuit Ckt_auth.
#[derive(Clone)]
pub struct AuthCircuit {
    pub public_inputs: AuthPublicInputs,
    pub witnesses: AuthPrivateWitnesses,
}

impl ConstraintSynthesizer<Fr> for AuthCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let config = poseidon_config_for_test::<Fr>();

        // Allocate public inputs
        let pk_op_x_var = FpVar::new_input(
            ark_relations::ns!(cs, "pk_op_x"), || Ok(self.public_inputs.pk_op_x))?;
        let pk_op_y_var = FpVar::new_input(
            ark_relations::ns!(cs, "pk_op_y"), || Ok(self.public_inputs.pk_op_y))?;
        let iss_var = FpVar::new_input(
            ark_relations::ns!(cs, "iss"), || Ok(self.public_inputs.iss))?;
        let t_exp_var = FpVar::new_input(
            ark_relations::ns!(cs, "t_exp"), || Ok(self.public_inputs.t_exp))?;
        let c_var = FpVar::new_input(
            ark_relations::ns!(cs, "ciphertext_c"), || Ok(self.public_inputs.ciphertext_c))?;

        // Allocate private witnesses
        let sub_var = FpVar::new_witness(
            ark_relations::ns!(cs, "sub"), || Ok(self.witnesses.sub))?;
        let r_x_var = FpVar::new_witness(
            ark_relations::ns!(cs, "r_x"), || Ok(self.witnesses.r_x))?;
        let r_y_var = FpVar::new_witness(
            ark_relations::ns!(cs, "r_y"), || Ok(self.witnesses.r_y))?;
        let s_var = FpVar::new_witness(
            ark_relations::ns!(cs, "s"), || Ok(self.witnesses.s))?;
        let k_var = FpVar::new_witness(
            ark_relations::ns!(cs, "k"), || Ok(self.witnesses.k))?;

        // Step 1: Token hash (~250 constraints)
        // h_τ = Poseidon(sub, iss, t_exp)
        let mut token_sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        token_sponge.absorb(&sub_var)?;
        token_sponge.absorb(&iss_var)?;
        token_sponge.absorb(&t_exp_var)?;
        let h_tau_var = token_sponge.squeeze_field_elements(1)?
            .into_iter().next().unwrap();

        // Step 2: EdDSA signature verification (~5,750 constraints)

        // 2a: Reconstruct R point
        let r_point_var = JubJubVar::new_witness(
            ark_relations::ns!(cs, "r_point"),
            || {
                Ok(ark_ed_on_bls12_381::EdwardsProjective::from(
                    JubJubAffine::new(self.witnesses.r_x, self.witnesses.r_y)
                ))
            },
        )?;
        r_point_var.x.enforce_equal(&r_x_var)?;
        r_point_var.y.enforce_equal(&r_y_var)?;

        // 2b: Compute challenge
        let mut challenge_sponge = PoseidonSpongeVar::new(cs.clone(), &config);
        challenge_sponge.absorb(&r_x_var)?;
        challenge_sponge.absorb(&r_y_var)?;
        challenge_sponge.absorb(&pk_op_x_var)?;
        challenge_sponge.absorb(&pk_op_y_var)?;
        challenge_sponge.absorb(&h_tau_var)?;
        let e_var = challenge_sponge.squeeze_field_elements(1)?
            .into_iter().next().unwrap();

        // 2c: P1 = [s] · B
        let generator_var = JubJubVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            ark_ed_on_bls12_381::EdwardsProjective::from(JubJubAffine::generator()),
        )?;
        let s_bits = s_var.to_bits_le()?;
        let p1_var = generator_var.scalar_mul_le(s_bits.iter())?;

        // 2d: P2 = R + [e] · pk_OP
        let pk_op_var = JubJubVar::new_witness(
            ark_relations::ns!(cs, "pk_op_point"),
            || {
                Ok(ark_ed_on_bls12_381::EdwardsProjective::from(
                    JubJubAffine::new(self.public_inputs.pk_op_x, self.public_inputs.pk_op_y)
                ))
            },
        )?;
        pk_op_var.x.enforce_equal(&pk_op_x_var)?;
        pk_op_var.y.enforce_equal(&pk_op_y_var)?;

        let e_bits = e_var.to_bits_le()?;
        let e_times_pk = pk_op_var.scalar_mul_le(e_bits.iter())?;
        let p2_var = r_point_var + e_times_pk;

        // 2e: Verify P1 == P2
        p1_var.enforce_equal(&p2_var)?;

        // Step 3: Identity binding (~1 constraint)
        // C = sub + K
        let c_computed = &sub_var + &k_var;
        c_var.enforce_equal(&c_computed)?;

        Ok(())
    }
}

// ============================================================
// Serialization helpers
// ============================================================

use std::io::{Read, Write};

pub fn write_eddsa_signature<W: Write>(
    w: &mut W,
    sig: &EdDSASignature,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::serialization::write_fr(w, &sig.r_point.x)?;
    crate::serialization::write_fr(w, &sig.r_point.y)?;
    crate::serialization::write_fr(w, &sig.s)?;
    Ok(())
}

pub fn read_eddsa_signature<R: Read>(
    r: &mut R,
) -> Result<EdDSASignature, Box<dyn std::error::Error>> {
    let r_x = crate::serialization::read_fr(r)?;
    let r_y = crate::serialization::read_fr(r)?;
    let s = crate::serialization::read_fr(r)?;
    Ok(EdDSASignature {
        r_point: JubJubAffine::new(r_x, r_y),
        s,
    })
}

pub fn write_zk_token<W: Write>(
    w: &mut W,
    token: &ZkToken,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::serialization::write_fr(w, &token.sub)?;
    crate::serialization::write_fr(w, &token.iss)?;
    crate::serialization::write_fr(w, &token.t_exp)?;
    write_eddsa_signature(w, &token.sigma)?;
    Ok(())
}

pub fn read_zk_token<R: Read>(
    r: &mut R,
) -> Result<ZkToken, Box<dyn std::error::Error>> {
    let sub = crate::serialization::read_fr(r)?;
    let iss = crate::serialization::read_fr(r)?;
    let t_exp = crate::serialization::read_fr(r)?;
    let sigma = read_eddsa_signature(r)?;
    Ok(ZkToken { sub, iss, t_exp, sigma })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::thread_rng;

    #[test]
    fn test_eddsa_sign_verify() {
        let mut rng = thread_rng();
        let kp = eddsa_keygen(&mut rng);
        let message = Fr::from(42u64);
        let sig = eddsa_sign(&mut rng, &kp.sk, &kp.pk, &message);
        assert!(eddsa_verify(&kp.pk, &sig, &message));

        let wrong_msg = Fr::from(99u64);
        assert!(!eddsa_verify(&kp.pk, &sig, &wrong_msg));
    }

    #[test]
    fn test_token_issue_verify() {
        let mut rng = thread_rng();
        let kp = eddsa_keygen(&mut rng);
        let sub = pack_email_to_field("alice@senderdomain.org");
        let iss = compute_iss("senderdomain.org");
        let t_exp = Fr::from(1000u64);
        let token = token_issue(&mut rng, &kp.sk, &kp.pk, &sub, &iss, &t_exp);
        assert!(token_verify(&kp.pk, &token));
    }

    #[test]
    fn test_auth_circuit_valid() {
        let mut rng = thread_rng();
        let kp = eddsa_keygen(&mut rng);
        let t_exp = Fr::from(1000u64);
        let sub = pack_email_to_field("alice@senderdomain.org");
        let iss = compute_iss("senderdomain.org");

        let token = token_issue(&mut rng, &kp.sk, &kp.pk, &sub, &iss, &t_exp);
        assert!(token_verify(&kp.pk, &token));

        let keystream_s = Fr::rand(&mut rng);
        let ciphertext_c = sub + keystream_s;

        let circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x,
                pk_op_y: kp.pk.y,
                iss,
                t_exp,
                ciphertext_c,
            },
            witnesses: AuthPrivateWitnesses {
                sub,
                r_x: token.sigma.r_point.x,
                r_y: token.sigma.r_point.y,
                s: token.sigma.s,
                k: keystream_s,
            },
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        eprintln!("[test] Auth circuit: {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_auth_circuit_impersonation_fails() {
        let mut rng = thread_rng();
        let kp = eddsa_keygen(&mut rng);
        let t_exp = Fr::from(1000u64);
        let iss = compute_iss("senderdomain.org");

        let sub_steve = pack_email_to_field("steve@senderdomain.org");
        let token_steve = token_issue(
            &mut rng, &kp.sk, &kp.pk, &sub_steve, &iss, &t_exp);

        let sub_alice = pack_email_to_field("alice@senderdomain.org");
        let keystream_s = Fr::rand(&mut rng);
        let ciphertext_c = sub_alice + keystream_s;

        let circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x,
                pk_op_y: kp.pk.y,
                iss,
                t_exp,
                ciphertext_c,
            },
            witnesses: AuthPrivateWitnesses {
                sub: sub_steve,
                r_x: token_steve.sigma.r_point.x,
                r_y: token_steve.sigma.r_point.y,
                s: token_steve.sigma.s,
                k: keystream_s,
            },
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(),
            "Impersonation should fail: C = alice + S but sub = steve");
    }
    // ============================================================
    // LegoGroth16 integration test for R_auth with c_id commitment
    // Add this test inside the `mod tests { ... }` block in zkauth.rs
    // ============================================================

    #[test]
    fn test_auth_legogroth16() {
        use ark_bls12_381::{Bls12_381, G1Projective};
        use ark_ec::{CurveGroup, Group as ArkGroup};
        use ark_ec::pairing::Pairing;
        use ark_ff::UniformRand;
        use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
        use std::time::Instant;

        let mut rng = thread_rng();

        // ── 1. Keygen + token ──────────────────────────────────
        let kp = eddsa_keygen(&mut rng);
        let t_exp = Fr::from(9999999999u64);
        let sub = pack_email_to_field("alice@senderdomain.org");
        let iss = compute_iss("senderdomain.org");
        let token = token_issue(&mut rng, &kp.sk, &kp.pk, &sub, &iss, &t_exp);
        assert!(token_verify(&kp.pk, &token), "Token should be valid");

        // ── 2. Simulate email encryption ───────────────────────
        let keystream_s = Fr::rand(&mut rng);
        let ciphertext_c = sub + keystream_s;   // C_s = sub + K_s

        // ── 3. LegoGroth16 Setup ───────────────────────────────
        eprintln!("[test] Running LegoGroth16 setup for R_auth...");
        let t0 = Instant::now();

        // Pedersen generators (g, h) — in production, share with CP_IdEnc
        let ped_g = G1Projective::rand(&mut rng);
        let ped_h = G1Projective::rand(&mut rng);

        let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
        let dummy_circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x,
                pk_op_y: kp.pk.y,
                iss,
                t_exp: Fr::from(1000u64),
                ciphertext_c: Fr::from(1u64),
            },
            witnesses: AuthPrivateWitnesses {
                sub: Fr::from(1u64),
                r_x: gen.x,
                r_y: gen.y,
                s: Fr::from(1u64),
                k: Fr::from(1u64),
            },
        };

        let link_gens = legogroth16::data_structures::LinkPublicGenerators::<Bls12_381> {
            pedersen_gens: vec![
                ped_g.into_affine(),
                ped_h.into_affine(),
            ],
            g1: <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine(),
            g2: <Bls12_381 as Pairing>::G2::rand(&mut rng).into_affine(),
        };

        let pk_lego = legogroth16::generate_random_parameters_incl_cp_link(
            dummy_circuit,
            link_gens,
            1,  // commit_witness_count = 1: commit to first witness (sub)
            &mut rng,
        ).expect("LegoGroth16 setup failed");

        let setup_time = t0.elapsed();
        eprintln!("[test] LegoGroth16 setup: {:.1?}", setup_time);

        // ── 4. Prove ───────────────────────────────────────────
        eprintln!("[test] Generating LegoGroth16 proof...");
        let t1 = Instant::now();

        let circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x,
                pk_op_y: kp.pk.y,
                iss,
                t_exp,
                ciphertext_c,
            },
            witnesses: AuthPrivateWitnesses {
                sub: token.sub,
                r_x: token.sigma.r_point.x,
                r_y: token.sigma.r_point.y,
                s: token.sigma.s,
                k: keystream_s,
            },
        };

        let v = Fr::rand(&mut rng);           // Groth16 ZK blinding
        let link_v = Fr::rand(&mut rng);      // Pedersen randomness r_m

        let proof = legogroth16::create_random_proof_incl_cp_link::<Bls12_381, _, _>(
            circuit,
            v,
            link_v,
            &pk_lego,
            &mut rng,
        ).expect("LegoGroth16 proof failed");

        let prove_time = t1.elapsed();
        eprintln!("[test] LegoGroth16 prove: {:.1?}", prove_time);

        // Extract c_id' = link_d
        let c_id_prime = proof.link_d.into_group();
        eprintln!("[test] c_id' (link_d) extracted");

        // ── 5. Verify ──────────────────────────────────────────
        eprintln!("[test] Verifying LegoGroth16 proof...");
        let t2 = Instant::now();

        let public_inputs = vec![
            kp.pk.x,
            kp.pk.y,
            iss,
            t_exp,
            ciphertext_c,
        ];

        let pvk = legogroth16::prepare_verifying_key(&pk_lego.vk.groth16_vk);
        legogroth16::verify_proof_incl_cp_link(
            &pvk,
            &pk_lego.vk,
            &proof,
            &public_inputs,
        ).expect("LegoGroth16 verification failed");

        let verify_time = t2.elapsed();
        eprintln!("[test] LegoGroth16 verify: {:.1?}", verify_time);

        // ── 6. Manually verify commitment matches ──────────────
        // Compute expected c_id = g^sub · h^r_m
        let expected_c_id = ped_g.mul_bigint(sub.into_bigint())
            + ped_h.mul_bigint(link_v.into_bigint());
        assert_eq!(c_id_prime, expected_c_id,
            "c_id' from proof must match manually computed Com(sub, r_m)");
        eprintln!("[test] ✓ c_id' == Com(sub, r_m) — commitment matches!");

        // ── 7. Test impersonation attack ───────────────────────
        // Alice tries to prove with sub=alice but C encrypts eve
        eprintln!("[test] Testing impersonation attack...");

        let sub_eve = pack_email_to_field("eve@senderdomain.org");
        let keystream_eve = Fr::rand(&mut rng);
        let ciphertext_eve = sub_eve + keystream_eve;  // C encrypts eve

        let attack_circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x,
                pk_op_y: kp.pk.y,
                iss,
                t_exp,
                ciphertext_c: ciphertext_eve,  // C encrypts eve
            },
            witnesses: AuthPrivateWitnesses {
                sub: token.sub,  // but alice's token
                r_x: token.sigma.r_point.x,
                r_y: token.sigma.r_point.y,
                s: token.sigma.s,
                k: keystream_eve,  // alice uses k' = C_eve - sub_alice
            },
        };

        // This should fail because C = eve + K but sub = alice
        // So C != sub + k (the circuit constraint)
        let cs = ConstraintSystem::<Fr>::new_ref();
        attack_circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(),
            "Impersonation attack must fail: C = eve + K but sub = alice");
        eprintln!("[test] ✓ Impersonation attack correctly rejected");

        // ── 8. Proof size ──────────────────────────────────────
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let mut c_id_bytes = Vec::new();
        c_id_prime.serialize_compressed(&mut c_id_bytes).unwrap();

        eprintln!("\n=== LegoGroth16 Auth Results ===");
        eprintln!("Setup time:    {:.1?}", setup_time);
        eprintln!("Prove time:    {:.1?}", prove_time);
        eprintln!("Verify time:   {:.1?}", verify_time);
        eprintln!("Proof size:    {} bytes (ProofWithLink)", proof_bytes.len());
        eprintln!("c_id' size:    {} bytes (G1 point)", c_id_bytes.len());
        eprintln!("Commitment:    c_id' == Com(sub, r_m) ✓");
        eprintln!("Impersonation: blocked ✓");
    }
    #[test]
    fn bench_auth_legogroth16_scaling() {
        use ark_bls12_381::{Bls12_381, G1Projective};
        use ark_ec::{CurveGroup, Group as ArkGroup};
        use ark_ec::pairing::Pairing;
        use ark_ff::UniformRand;
        use std::time::Instant;

        let mut rng = thread_rng();

        let kp = eddsa_keygen(&mut rng);
        let t_exp = Fr::from(9999999999u64);
        let sub = pack_email_to_field("alice@senderdomain.org");
        let iss = compute_iss("senderdomain.org");
        let token = token_issue(&mut rng, &kp.sk, &kp.pk, &sub, &iss, &t_exp);

        let keystream_s = Fr::rand(&mut rng);
        let ciphertext_c = sub + keystream_s;

        let ped_g = G1Projective::rand(&mut rng);
        let ped_h = G1Projective::rand(&mut rng);

        let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
        let dummy_circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                iss, t_exp: Fr::from(1000u64),
                ciphertext_c: Fr::from(1u64),
            },
            witnesses: AuthPrivateWitnesses {
                sub: Fr::from(1u64),
                r_x: gen.x, r_y: gen.y,
                s: Fr::from(1u64), k: Fr::from(1u64),
            },
        };

        let link_gens = legogroth16::data_structures::LinkPublicGenerators::<Bls12_381> {
            pedersen_gens: vec![ped_g.into_affine(), ped_h.into_affine()],
            g1: <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine(),
            g2: <Bls12_381 as Pairing>::G2::rand(&mut rng).into_affine(),
        };

        let pk_lego = legogroth16::generate_random_parameters_incl_cp_link(
            dummy_circuit, link_gens, 1, &mut rng,
        ).expect("setup failed");

        let thread_counts = [1, 2, 4, 6, 8, 10, 12, 14, 16];

        eprintln!("\n=== LegoGroth16 Auth Parallel Scaling ===");
        eprintln!("Threads | Prove (ms)");
        eprintln!("--------|----------");

        for &threads in &thread_counts {
            std::env::set_var("RAYON_NUM_THREADS", threads.to_string());

            // Warm-up
            {
                let c = AuthCircuit {
                    public_inputs: AuthPublicInputs {
                        pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                        iss, t_exp, ciphertext_c,
                    },
                    witnesses: AuthPrivateWitnesses {
                        sub: token.sub,
                        r_x: token.sigma.r_point.x,
                        r_y: token.sigma.r_point.y,
                        s: token.sigma.s, k: keystream_s,
                    },
                };
                let v = Fr::rand(&mut rng);
                let lv = Fr::rand(&mut rng);
                let _ = legogroth16::create_random_proof_incl_cp_link::<Bls12_381, _, _>(
                    c, v, lv, &pk_lego, &mut rng,
                );
            }

            // Median of 3
            let mut times = Vec::new();
            for _ in 0..3 {
                let c = AuthCircuit {
                    public_inputs: AuthPublicInputs {
                        pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                        iss, t_exp, ciphertext_c,
                    },
                    witnesses: AuthPrivateWitnesses {
                        sub: token.sub,
                        r_x: token.sigma.r_point.x,
                        r_y: token.sigma.r_point.y,
                        s: token.sigma.s, k: keystream_s,
                    },
                };
                let v = Fr::rand(&mut rng);
                let lv = Fr::rand(&mut rng);
                let t = Instant::now();
                let _ = legogroth16::create_random_proof_incl_cp_link::<Bls12_381, _, _>(
                    c, v, lv, &pk_lego, &mut rng,
                ).unwrap();
                times.push(t.elapsed().as_millis());
            }
            times.sort();
            eprintln!("{:>7} | {}", threads, times[1]);
        }

        // Also measure verify and CRS gen
        let circuit = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                iss, t_exp, ciphertext_c,
            },
            witnesses: AuthPrivateWitnesses {
                sub: token.sub,
                r_x: token.sigma.r_point.x,
                r_y: token.sigma.r_point.y,
                s: token.sigma.s, k: keystream_s,
            },
        };
        let v = Fr::rand(&mut rng);
        let lv = Fr::rand(&mut rng);
        let proof = legogroth16::create_random_proof_incl_cp_link::<Bls12_381, _, _>(
            circuit, v, lv, &pk_lego, &mut rng,
        ).unwrap();

        let public_inputs = vec![kp.pk.x, kp.pk.y, iss, t_exp, ciphertext_c];
        let pvk = legogroth16::prepare_verifying_key(&pk_lego.vk.groth16_vk);

        let mut vtimes = Vec::new();
        for _ in 0..3 {
            let t = Instant::now();
            legogroth16::verify_proof_incl_cp_link(&pvk, &pk_lego.vk, &proof, &public_inputs).unwrap();
            vtimes.push(t.elapsed().as_micros());
        }
        vtimes.sort();
        eprintln!("\nVerify (median): {} µs", vtimes[1]);

        // CRS gen
        let dummy2 = AuthCircuit {
            public_inputs: AuthPublicInputs {
                pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                iss, t_exp: Fr::from(1000u64),
                ciphertext_c: Fr::from(1u64),
            },
            witnesses: AuthPrivateWitnesses {
                sub: Fr::from(1u64),
                r_x: gen.x, r_y: gen.y,
                s: Fr::from(1u64), k: Fr::from(1u64),
            },
        };
        let link_gens2 = legogroth16::data_structures::LinkPublicGenerators::<Bls12_381> {
            pedersen_gens: vec![ped_g.into_affine(), ped_h.into_affine()],
            g1: <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine(),
            g2: <Bls12_381 as Pairing>::G2::rand(&mut rng).into_affine(),
        };
        let t = Instant::now();
        let _ = legogroth16::generate_random_parameters_incl_cp_link(
            dummy2, link_gens2, 1, &mut rng,
        ).unwrap();
        eprintln!("CRS gen: {} ms", t.elapsed().as_millis());
    }
    #[test]
    fn bench_auth_receiver_groth16() {
        use ark_bls12_381::Bls12_381;
        use ark_ff::UniformRand;
        use ark_serialize::CanonicalSerialize;
        use ark_relations::r1cs::SynthesisError;
        use ark_groth16::Groth16;
        use ark_snark::SNARK;
        use std::time::Instant;

        #[derive(Clone)]
        struct ReceiverAuthCircuit {
            inner: AuthCircuit,
            dummy_witnesses: Vec<Fr>,
        }

        impl ConstraintSynthesizer<Fr> for ReceiverAuthCircuit {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<Fr>,
            ) -> Result<(), SynthesisError> {
                let dummies = self.dummy_witnesses.clone();
                self.inner.generate_constraints(cs.clone())?;
                for i in 0..5029 {
                    let a = FpVar::new_witness(cs.clone(), || {
                        Ok(dummies.get(i*2)
                            .copied().unwrap_or(Fr::from(1u64)))
                    })?;
                    let b = FpVar::new_witness(cs.clone(), || {
                        Ok(dummies.get(i*2+1)
                            .copied().unwrap_or(Fr::from(1u64)))
                    })?;
                    let _c = &a * &b;
                }
                Ok(())
            }
        }

        let mut rng = thread_rng();

        let kp = eddsa_keygen(&mut rng);
        let t_exp = Fr::from(9999999999u64);
        let sub = pack_email_to_field("alice@senderdomain.org");
        let iss = compute_iss("senderdomain.org");
        let token = token_issue(&mut rng, &kp.sk, &kp.pk, &sub, &iss, &t_exp);

        let keystream_s = Fr::rand(&mut rng);
        let ciphertext_c = sub + keystream_s;

        let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
        let dummy_wits: Vec<Fr> = (0..10058).map(|_| Fr::rand(&mut rng)).collect();

        let dummy_circuit = ReceiverAuthCircuit {
            inner: AuthCircuit {
                public_inputs: AuthPublicInputs {
                    pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                    iss, t_exp: Fr::from(1000u64),
                    ciphertext_c: Fr::from(1u64),
                },
                witnesses: AuthPrivateWitnesses {
                    sub: Fr::from(1u64),
                    r_x: gen.x, r_y: gen.y,
                    s: Fr::from(1u64), k: Fr::from(1u64),
                },
            },
            dummy_witnesses: dummy_wits.clone(),
        };

        // Setup
        let t0 = Instant::now();
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            dummy_circuit, &mut rng,
        ).expect("setup failed");
        let setup_ms = t0.elapsed().as_millis();

        // Prove (3 runs, median)
        let mut prove_times = Vec::new();
        for _ in 0..3 {
            let c = ReceiverAuthCircuit {
                inner: AuthCircuit {
                    public_inputs: AuthPublicInputs {
                        pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                        iss, t_exp, ciphertext_c,
                    },
                    witnesses: AuthPrivateWitnesses {
                        sub: token.sub,
                        r_x: token.sigma.r_point.x,
                        r_y: token.sigma.r_point.y,
                        s: token.sigma.s, k: keystream_s,
                    },
                },
                dummy_witnesses: dummy_wits.clone(),
            };
            let t1 = Instant::now();
            let _ = Groth16::<Bls12_381>::prove(&pk, c, &mut rng).unwrap();
            prove_times.push(t1.elapsed().as_millis());
        }
        prove_times.sort();

        // Verify
        let c = ReceiverAuthCircuit {
            inner: AuthCircuit {
                public_inputs: AuthPublicInputs {
                    pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                    iss, t_exp, ciphertext_c,
                },
                witnesses: AuthPrivateWitnesses {
                    sub: token.sub,
                    r_x: token.sigma.r_point.x,
                    r_y: token.sigma.r_point.y,
                    s: token.sigma.s, k: keystream_s,
                },
            },
            dummy_witnesses: dummy_wits.clone(),
        };
        let proof = Groth16::<Bls12_381>::prove(&pk, c, &mut rng).unwrap();

        let public_inputs = vec![kp.pk.x, kp.pk.y, iss, t_exp, ciphertext_c];
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
        let t2 = Instant::now();
        let valid = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();
        let verify_us = t2.elapsed().as_micros();
        assert!(valid, "proof must verify");

        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();

        // Constraint count
        let cs = ConstraintSystem::<Fr>::new_ref();
        let check_circuit = ReceiverAuthCircuit {
            inner: AuthCircuit {
                public_inputs: AuthPublicInputs {
                    pk_op_x: kp.pk.x, pk_op_y: kp.pk.y,
                    iss, t_exp, ciphertext_c,
                },
                witnesses: AuthPrivateWitnesses {
                    sub: token.sub,
                    r_x: token.sigma.r_point.x,
                    r_y: token.sigma.r_point.y,
                    s: token.sigma.s, k: keystream_s,
                },
            },
            dummy_witnesses: dummy_wits.clone(),
        };
        check_circuit.generate_constraints(cs.clone()).unwrap();

        eprintln!("\n=== Receiver Auth (Groth16, ~12,300 constraints) ===");
        eprintln!("Constraints: {}", cs.num_constraints());
        eprintln!("Setup:       {} ms", setup_ms);
        eprintln!("Prove:       {} ms (median of 3: {}, {}, {})",
            prove_times[1], prove_times[0], prove_times[1], prove_times[2]);
        eprintln!("Verify:      {} us", verify_us);
        eprintln!("PK size:     {} bytes ({} KB)", pk_bytes.len(), pk_bytes.len()/1024);
        eprintln!("VK size:     {} bytes", vk_bytes.len());
        eprintln!("Proof size:  {} bytes", proof_bytes.len());
    }

}
