//! Implements CPMemRSA and CPMemRSAPrm.
use crate::{
    commitments::{integer::IntegerCommitment, pedersen::PedersenCommitment, Commitment},
    parameters::Parameters,
    protocols::{
        hash_to_prime::{
            channel::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
            CRSHashToPrime, HashToPrimeError, HashToPrimeProtocol,
            Statement as HashToPrimeStatement, Witness as HashToPrimeWitness,
        },
        modeq::{
            channel::{ModEqProverChannel, ModEqVerifierChannel},
            CRSModEq, Proof as ModEqProof, Protocol as ModEqProtocol, Statement as ModEqStatement,
            Witness as ModEqWitness,
        },
        root::{
            channel::{RootProverChannel, RootVerifierChannel},
            CRSRoot, Proof as RootProof, Protocol as RootProtocol, Statement as RootStatement,
            Witness as RootWitness,
        },
        ProofError, SetupError, VerificationError,
    },
    utils::ConvertibleUnknownOrderGroup,
    utils::{curve::CurvePointProjective, random_between},
};
use channel::{MembershipProverChannel, MembershipVerifierChannel};
use rand::{CryptoRng, RngCore};
use rug::rand::MutRandState;
use rug::Integer;

pub mod channel;
pub mod transcript;

pub struct CRS<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>>
{
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub crs_root: CRSRoot<G>,
    pub crs_modeq: CRSModEq<G, P>,
    pub crs_hash_to_prime: CRSHashToPrime<P, HP>,
}

impl<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>> Clone
    for CRS<G, P, HP>
{
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            crs_root: self.crs_root.clone(),
            crs_modeq: self.crs_modeq.clone(),
            crs_hash_to_prime: self.crs_hash_to_prime.clone(),
        }
    }
}

pub struct Protocol<
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
    HP: HashToPrimeProtocol<P>,
> {
    pub crs: CRS<G, P, HP>,
}

pub struct Statement<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    pub c_p: G::Elem,
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
    pub nc: Option<ark_bls12_381::Fr>,
    pub ciphertext: Option<ark_bls12_381::Fr>,
}

pub struct Witness<G: ConvertibleUnknownOrderGroup> {
    pub e: Integer,
    pub r_q: Integer,
    pub w: G::Elem,
    pub e_sec: Option<ark_bls12_381::Fr>,
    pub email_bytes: Option<Vec<u8>>,
    pub u_y: Option<Integer>,
}

pub struct Proof<
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
    HP: HashToPrimeProtocol<P>,
> {
    pub c_e: <IntegerCommitment<G> as Commitment>::Instance,
    pub proof_root: RootProof<G>,
    pub proof_modeq: ModEqProof<G, P>,
    pub proof_hash_to_prime: HP::Proof,
}

impl<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>> Clone
    for Proof<G, P, HP>
{
    fn clone(&self) -> Self {
        Self {
            c_e: self.c_e.clone(),
            proof_root: self.proof_root.clone(),
            proof_modeq: self.proof_modeq.clone(),
            proof_hash_to_prime: self.proof_hash_to_prime.clone(),
        }
    }
}

impl<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>>
    Protocol<G, P, HP>
{
    pub fn setup<R1: MutRandState, R2: RngCore + CryptoRng>(
        parameters: &Parameters,
        rng1: &mut R1,
        rng2: &mut R2,
    ) -> Result<Protocol<G, P, HP>, SetupError> {
        let integer_commitment_parameters = IntegerCommitment::<G>::setup(rng1);
        let pedersen_commitment_parameters = PedersenCommitment::<P>::setup(rng2);
        let hash_to_prime_parameters =
            HP::setup(rng2, &pedersen_commitment_parameters, parameters)?;
        Ok(Protocol {
            crs: CRS::<G, P, HP> {
                parameters: parameters.clone(),
                crs_modeq: CRSModEq::<G, P> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                    pedersen_commitment_parameters: pedersen_commitment_parameters.clone(),
                },
                crs_root: CRSRoot::<G> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters,
                },
                crs_hash_to_prime: CRSHashToPrime::<P, HP> {
                    parameters: parameters.clone(),
                    pedersen_commitment_parameters,
                    hash_to_prime_parameters,
                },
            },
        })
    }

    pub fn prove<
        R1: MutRandState,
        R2: RngCore + CryptoRng,
        C: MembershipVerifierChannel<G>
            + RootVerifierChannel<G>
            + ModEqVerifierChannel<G, P>
            + HashToPrimeVerifierChannel<P, HP>,
    >(
        &self,
        verifier_channel: &mut C,
        rng1: &mut R1,
        rng2: &mut R2,
        statement: &Statement<G, P>,
        witness: &Witness<G>,
    ) -> Result<(), ProofError> {
        let (hashed_e, _) = self.hash_to_prime_with_key(&witness.e, &witness.u_y)?;
        let r = random_between(rng1, &Integer::from(0), &G::order_upper_bound());
        let c_e = self
            .crs
            .crs_root
            .integer_commitment_parameters
            .commit(&hashed_e, &r)?;
        verifier_channel.send_c_e(&c_e)?;
        let root = RootProtocol::from_crs(&self.crs.crs_root);
        root.prove(
            verifier_channel,
            rng1,
            &RootStatement {
                c_e: c_e.clone(),
                acc: statement.c_p.clone(),
            },
            &RootWitness {
                e: hashed_e.clone(),
                r: r.clone(),
                w: witness.w.clone(),
            },
        )?;
        let modeq = ModEqProtocol::from_crs(&self.crs.crs_modeq);
        modeq.prove(
            verifier_channel,
            rng1,
            rng2,
            &ModEqStatement {
                c_e,
                c_e_q: statement.c_e_q.clone(),
            },
            &ModEqWitness {
                e: hashed_e,
                r,
                r_q: witness.r_q.clone(),
            },
        )?;
        let hash_to_prime = HashToPrimeProtocol::from_crs(&self.crs.crs_hash_to_prime);
        hash_to_prime.prove(
            verifier_channel,
            rng2,
            &HashToPrimeStatement {
                c_e_q: statement.c_e_q.clone(), nc: statement.nc, ciphertext: statement.ciphertext,
            },
            &HashToPrimeWitness {
                e: witness.e.clone(),
                r_q: witness.r_q.clone(),
                u_y: witness.u_y.clone(),
                e_sec: witness.e_sec,
                email_bytes: witness.email_bytes.clone(),
            },
        )?;

        Ok(())
    }

    pub fn verify<
        C: MembershipProverChannel<G>
            + RootProverChannel<G>
            + ModEqProverChannel<G, P>
            + HashToPrimeProverChannel<P, HP>,
    >(
        &self,
        prover_channel: &mut C,
        statement: &Statement<G, P>,
    ) -> Result<(), VerificationError> {
        let c_e = prover_channel.receive_c_e()?;
        let root = RootProtocol::from_crs(&self.crs.crs_root);
        root.verify(
            prover_channel,
            &RootStatement {
                c_e: c_e.clone(),
                acc: statement.c_p.clone(),
            },
        )?;
        let modeq = ModEqProtocol::from_crs(&self.crs.crs_modeq);
        modeq.verify(
            prover_channel,
            &ModEqStatement {
                c_e,
                c_e_q: statement.c_e_q.clone(),
            },
        )?;
        let hash_to_prime = HashToPrimeProtocol::from_crs(&self.crs.crs_hash_to_prime);
        hash_to_prime.verify(
            prover_channel,
            &HashToPrimeStatement {
                c_e_q: statement.c_e_q.clone(), nc: statement.nc, ciphertext: statement.ciphertext,
            },
        )?;

        Ok(())
    }

    pub fn hash_to_prime(&self, e: &Integer) -> Result<(Integer, u64), HashToPrimeError> {
        let hash_to_prime = HashToPrimeProtocol::from_crs(&self.crs.crs_hash_to_prime);
        hash_to_prime.hash_to_prime(e, None)
    }

    pub fn hash_to_prime_with_key(&self, e: &Integer, u_y: &Option<Integer>) -> Result<(Integer, u64), HashToPrimeError> {
        let hash_to_prime = HashToPrimeProtocol::from_crs(&self.crs.crs_hash_to_prime);
        match u_y {
            Some(uy) => hash_to_prime.hash_to_prime(e, Some((e, uy))),
            None => hash_to_prime.hash_to_prime(e, None),
        }
    }

    pub fn from_crs(crs: &CRS<G, P, HP>) -> Protocol<G, P, HP> {
        Protocol { crs: crs.clone() }
    }
}

#[cfg(all(test, feature = "arkworks"))]
mod test {
    use super::{Protocol, Statement, Witness};
    use crate::{
        commitments::Commitment,
        parameters::Parameters,
        protocols::{
            hash_to_prime::snark_hash::{HashToPrimeHashParameters, Protocol as HPProtocol, test::TestParameters},
            membership::transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
        },
    };
    use accumulator::group::{ClassGroup, Rsa2048};
    use accumulator::{group::Group, AccumulatorWithoutHashToPrime};
    use ark_bls12_381::{Bls12_381, G1Projective};
    use merlin::Transcript;
    use rand::thread_rng;
    use rug::rand::RandState;
    use rug::Integer;
    use std::cell::RefCell;

    const LARGE_PRIMES: [u64; 4] = [
        553_525_575_239_331_913,
        12_702_637_924_034_044_211,
        378_373_571_372_703_133,
        8_640_171_141_336_142_787,
    ];

    #[test]
    #[ignore]
    fn test_e2e_prime_rsa() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();
        let crs = crate::protocols::membership::Protocol::<
            Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2).unwrap().crs;
        let protocol = Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>>::from_crs(&crs);
        let value = Integer::from(Integer::u_pow_u(2, (crs.parameters.hash_to_prime_bits) as u32)) - &Integer::from(245);
        let randomness = Integer::from(5);
        let commitment = protocol.crs.crs_modeq.pedersen_commitment_parameters.commit(&value, &randomness).unwrap();
        let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());
        let accum = accum.add_with_proof(&[value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(Rsa2048::exp(&w, &value), acc);
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement { c_e_q: commitment, c_p: acc, nc: None, ciphertext: None };
        protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness { e: value, r_q: randomness, w, e_sec: None, email_bytes: None, u_y: None }).unwrap();
        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }

    #[test]
    #[ignore]
    fn test_e2e_prime_class_group() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();
        let crs = crate::protocols::membership::Protocol::<
            ClassGroup, G1Projective, HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2).unwrap().crs;
        let protocol = Protocol::<ClassGroup, G1Projective, HPProtocol<Bls12_381, TestParameters>>::from_crs(&crs);
        let value = Integer::from(Integer::u_pow_u(2, (crs.parameters.hash_to_prime_bits) as u32)) - &Integer::from(245);
        let randomness = Integer::from(5);
        let commitment = protocol.crs.crs_modeq.pedersen_commitment_parameters.commit(&value, &randomness).unwrap();
        let accum = accumulator::Accumulator::<ClassGroup, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());
        let accum = accum.add_with_proof(&[value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(ClassGroup::exp(&w, &value), acc);
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement { c_e_q: commitment, c_p: acc, nc: None, ciphertext: None };
        protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness { e: value, r_q: randomness, w, e_sec: None, email_bytes: None, u_y: None }).unwrap();
        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }

    #[test]
    fn test_e2e_hash_to_prime() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();
        let crs = crate::protocols::membership::Protocol::<
            Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2).unwrap().crs;
        let protocol = Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>>::from_crs(&crs);
        let value = Integer::from(24_928_329);
        let (hashed_value, _) = protocol.hash_to_prime(&value).unwrap();
        let randomness = Integer::from(5);
        let commitment = protocol.crs.crs_modeq.pedersen_commitment_parameters.commit(&hashed_value, &randomness).unwrap();
        let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());
        let accum = accum.add_with_proof(&[hashed_value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(Rsa2048::exp(&w, &hashed_value), acc);
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement { c_e_q: commitment, c_p: acc, nc: None, ciphertext: None };
        protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness { e: value, r_q: randomness, w, e_sec: None, email_bytes: None, u_y: None }).unwrap();
        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
    #[test]
    fn bench_full_membership() {
        use crate::protocols::hash_to_prime::snark_hash::PoseidonProtocol;
        use std::time::Instant;

        let params = Parameters::from_security_level(128).unwrap();

        // ============================================================
        // Blake2s full membership proof
        // ============================================================
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let blake_crs = crate::protocols::membership::Protocol::<
            Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2).unwrap().crs;
        let blake_protocol = Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>>::from_crs(&blake_crs);

        let value = Integer::from(24_928_329);
        let (blake_hashed, _) = blake_protocol.hash_to_prime(&value).unwrap();
        let randomness = Integer::from(5);
        let blake_commitment = blake_protocol.crs.crs_modeq.pedersen_commitment_parameters.commit(&blake_hashed, &randomness).unwrap();
        let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());
        let accum = accum.add_with_proof(&[blake_hashed.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;

        let blake_prove_start = Instant::now();
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&blake_crs, &proof_transcript);
        let statement = Statement { c_e_q: blake_commitment, c_p: acc.clone(), nc: None, ciphertext: None };
        blake_protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness { e: value.clone(), r_q: randomness.clone(), w: w.clone(), e_sec: None, email_bytes: None, u_y: None }).unwrap();
        let blake_prove_time = blake_prove_start.elapsed();
        let proof = verifier_channel.proof().unwrap();

        let blake_verify_start = Instant::now();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel = TranscriptProverChannel::new(&blake_crs, &verification_transcript, &proof);
        blake_protocol.verify(&mut prover_channel, &statement).unwrap();
        let blake_verify_time = blake_verify_start.elapsed();

        // ============================================================
        // Poseidon full membership proof
        // ============================================================
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));

        let poseidon_crs = crate::protocols::membership::Protocol::<
            Rsa2048, G1Projective, PoseidonProtocol<Bls12_381>,
        >::setup(&params, &mut rng1, &mut rng2).unwrap().crs;
        let poseidon_protocol = Protocol::<Rsa2048, G1Projective, PoseidonProtocol<Bls12_381>>::from_crs(&poseidon_crs);

        let value = Integer::from(24_928_329);
        let (poseidon_hashed, _) = poseidon_protocol.hash_to_prime(&value).unwrap();
        let randomness = Integer::from(5);
        let poseidon_commitment = poseidon_protocol.crs.crs_modeq.pedersen_commitment_parameters.commit(&poseidon_hashed, &randomness).unwrap();
        let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());
        let accum = accum.add_with_proof(&[poseidon_hashed.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;

        // Native computation of C
        use ark_ff::{UniformRand, PrimeField};
        use ark_ec::{AffineRepr, CurveGroup, Group};
        use ark_crypto_primitives::sponge::CryptographicSponge;
        use ark_bls12_381::Fr;

        let salt = Fr::from(12345u64);
        let info = Fr::from(67890u64);
        let nc = Fr::from(1u64);
        let email_bytes = b"alice@example.com".to_vec();
        let e_sec = Fr::rand(&mut rng2);

        let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
        let shared_key = gen.mul_bigint(e_sec.into_bigint());
        let shared_affine = shared_key.into_affine();

        let poseidon_config = crate::protocols::hash_to_prime::snark_hash::poseidon_config_for_test::<Fr>();
        let mut kdf_sponge = ark_crypto_primitives::sponge::poseidon::PoseidonSponge::new(&poseidon_config);
        kdf_sponge.absorb(&salt);
        kdf_sponge.absorb(&shared_affine.x);
        kdf_sponge.absorb(&shared_affine.y);
        kdf_sponge.absorb(&info);
        let k_pos: Fr = kdf_sponge.squeeze_field_elements(1)[0];

        let mut m_native = Fr::from(0u64);
        let mut power = Fr::from(1u64);
        for i in 0..31usize {
            let byte_val = if i < email_bytes.len() { Fr::from(email_bytes[i] as u64) } else { Fr::from(0u64) };
            m_native += byte_val * power;
            power *= Fr::from(256u64);
        }

        let mut enc_sponge = ark_crypto_primitives::sponge::poseidon::PoseidonSponge::new(&poseidon_config);
        enc_sponge.absorb(&salt);
        enc_sponge.absorb(&k_pos);
        enc_sponge.absorb(&nc);
        let keystream: Fr = enc_sponge.squeeze_field_elements(1)[0];
        let ciphertext_native = m_native + keystream;

        let poseidon_prove_start = Instant::now();
        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&poseidon_crs, &proof_transcript);
        let statement = Statement { c_e_q: poseidon_commitment, c_p: acc.clone(), nc: Some(nc), ciphertext: Some(ciphertext_native) };
        poseidon_protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness { e: value.clone(), r_q: randomness.clone(), w: w.clone(), e_sec: Some(e_sec), email_bytes: Some(email_bytes), u_y: None }).unwrap();
        let poseidon_prove_time = poseidon_prove_start.elapsed();
        let proof = verifier_channel.proof().unwrap();

        let poseidon_verify_start = Instant::now();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel = TranscriptProverChannel::new(&poseidon_crs, &verification_transcript, &proof);
        poseidon_protocol.verify(&mut prover_channel, &statement).unwrap();
        let poseidon_verify_time = poseidon_verify_start.elapsed();

        // ============================================================
        // Results
        // ============================================================
        println!("\n=== Full Membership Proof Benchmark (CPRoot + CPmodEq + CP_IdEnc) ===\n");
        println!("                 Blake2s         Poseidon+ECDH+Enc   Ratio");
        println!("Prove time:      {:>12.1?}    {:>12.1?}         {:.2}x",
            blake_prove_time, poseidon_prove_time,
            blake_prove_time.as_secs_f64() / poseidon_prove_time.as_secs_f64());
        println!("Verify time:     {:>12.1?}    {:>12.1?}         {:.2}x",
            blake_verify_time, poseidon_verify_time,
            blake_verify_time.as_secs_f64() / poseidon_verify_time.as_secs_f64());
        println!("\nNote: Poseidon circuit includes hash-to-prime + EC DH + KDF + byte packing + keystream + encryption");
    }
}