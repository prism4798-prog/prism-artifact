//! LegoGroth16-based hash-to-prime proof, with Blake2s and Poseidon as the hash.

use crate::{
    commitments::pedersen::PedersenCommitment,
    parameters::Parameters,
    protocols::{
        hash_to_prime::{
            channel::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
            CRSHashToPrime, HashToPrimeError, HashToPrimeProtocol, Statement, Witness,
        },
        ProofError, SetupError, VerificationError,
    },
    utils::{
        bigint_to_integer, bits_big_endian_to_bytes_big_endian,
        bytes_big_endian_to_bits_big_endian, integer_to_bigint_mod_q, log2,
    },
};
//deals with the finite field
use ark_ff::{
    BigInteger, One, PrimeField, UniformRand,
};
//deals with the elliptic curve
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::Group;
use ark_bls12_381::Fr as BlsFr;

use ark_ed_on_bls12_381::{self, constraints::EdwardsVar as JubJubVar, EdwardsConfig as JubJubConfig};
use ark_r1cs_std::groups::CurveVar;

//for doing the hash outside for regular hash to prim
use blake2::{Blake2s256, Digest};
//hash to prime inside the snark
use ark_crypto_primitives::{prf::blake2s::constraints::evaluate_blake2s};
//ConstraintSynthesizer - trait "i can generate R1CS constraints" the circuit must implement this
//ConstraintSystemRef - the constraint system we add constraint to
//SynthesisError - error type for circuit building

// Poseidon hash — SNARK-friendly hash function that operates natively on field elements.
// PoseidonConfig: holds the configuration (rate, rounds, MDS matrix, round constants).
// PoseidonSpongeVar: the circuit version of Poseidon sponge — absorbs FpVars and squeezes FpVars.
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, constraints::PoseidonSpongeVar};
// CryptographicSpongeVar: trait that PoseidonSpongeVar implements — provides absorb() and squeeze().
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
// Absorb: trait that field elements must implement to be absorbed into a Poseidon sponge.
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
// ark_r1cs_std:
//     AllocVar / AllocationMode → allocate variables in the circuit
//         AllocationMode::Witness → private variable (prover knows, verifier doesn't)
//         AllocationMode::Input   → public variable (both know)
// Boolean         → a boolean variable inside the circuit (not Rust bool!)
// FpVar           → a field element variable inside the circuit (not Rust integer!)
// ToBitsGadget    → convert circuit variables to bits
// EqGadget        → enforce equality between circuit variables
// Assignment      → helper for getting values during witness generation
// R1CSVar         → base trait for circuit variables
use ark_r1cs_std::{
    alloc::{AllocationMode, AllocVar}, bits::ToBitsGadget, boolean::Boolean, eq::EqGadget, fields::fp::FpVar,
    Assignment, R1CSVar,
};

// rand::Rng          → random number generation trait
// rug::IsPrime       → primality testing result (Yes/No/Probably)
// rug::Integer       → GMP big integers
// Neg, Sub           → traits for negation and subtraction operators
use rand::Rng;
use rug::{integer::IsPrime, Integer};
use std::ops::{Neg, Sub};


// A trait (interface) that defines configuration for hash-to-prime
// Anyone using this protocol must implement this with their specific sizes
pub trait HashToPrimeHashParameters {

    // How many bits is the input u?
    // For the test: 254 bits
    // For our case: bit-size of the EC public key
    const MESSAGE_SIZE: u16;

    // How many bits does the counter j need?
    // j is the counter that increments until we find a prime
    // Paper: κ in H(u, j) where j ∈ [0, 2^κ - 1]
    fn index_bit_length(security_level: u16) -> u64 {
        // security_level = 128, MESSAGE_SIZE = 254
        // 128 * 254 = 32512
        // log2(32512) ≈ 15
        // So j needs 15 bits → can try up to 32768 times
        log2((security_level as usize) * (Self::MESSAGE_SIZE as usize)) as u64
    }
}

// The SNARK circuit that proves "I correctly hashed u to a prime e".
// This generates R1CS constraints for LegoGroth16.
// Two generic types:
//   E: Pairing — the elliptic curve (BLS12-381 in our test)
//   P: HashToPrimeHashParameters — configuration (MESSAGE_SIZE, index_bit_length)
pub struct HashToPrimeHashCircuit<E: Pairing, P: HashToPrimeHashParameters> {
    // ωs from the paper — security parameter (e.g., 128)
    security_level: u16,
    // µ from the paper — how many bits the output prime must be
    required_bit_size: u16,
    // The secret input u (the arbitrary value being hashed to prime).
    // Type is E::ScalarField — a field element in the scalar field of the curve.
    // Option because during setup, the circuit is built WITHOUT actual values (None)
    // just to determine the circuit shape. During proving, it's Some(u).
    value: Option<E::ScalarField>,
    // The counter j found by the native hash_to_prime() in Step 1.
    // "hash(u, j) produced a prime" — j is already known before circuit runs.
    // Option for the same reason — None during setup, Some(j) during proving.
    index: Option<u64>,
    // PhantomData tells Rust "I use P in my type signature but not in my fields".
    // Without this, Rust would complain that P is unused.
    // It has zero size — takes no memory at runtime.
    prime: Option<E::ScalarField>,
    parameters_type: std::marker::PhantomData<P>,
    // Note: the output e (the prime) is computed INSIDE the circuit
    // and linked to the Pedersen commitment c_e_q via LegoGroth16.
    // The verifier never sees u, j, or e — only c_e_q.
}

/// Poseidon-based hash-to-prime circuit.
/// Takes JubJub curve point coordinates (u_x, u_y) and counter j as native field elements.
/// JubJub Fq = BLS12-381 Fr — so u_x, u_y fit directly in FpVar.
/// No bit conversion needed for hashing — Poseidon absorbs field elements directly.
/// poseidon_config holds the precomputed Poseidon parameters (MDS matrix, round constants).
pub struct PoseidonHashToPrimeCircuit<E: Pairing> where E::ScalarField: Absorb {
    pub required_bit_size: u16,
    /// x-coordinate of JubJub public key
    pub u_x: Option<E::ScalarField>,
    /// y-coordinate of JubJub public key
    pub u_y: Option<E::ScalarField>,
    /// Counter j as a field element
    pub index: Option<E::ScalarField>,
    /// The precomputed prime e = 1|H(u_x, u_y, j).
    /// Allocated as FIRST Witness for Dock's legogroth16 commitment.
    pub prime: Option<E::ScalarField>,

    /// Ephemeral secret scalar for EC Diffie-Hellman. None during setup, Some during proving.
    pub e_sec: Option<E::ScalarField>,
    /// Domain separation salt — fixed in CRS
    pub salt: E::ScalarField,
    /// Context binding info — fixed in CRS
    pub info: E::ScalarField,
    /// Email address bytes — secret witness, max 31 bytes
    pub email_bytes: Option<Vec<u8>>,
    /// Per-message nonce — public input, verifier checks this
    pub nc: Option<E::ScalarField>,
    /// Poseidon parameters
    pub poseidon_config: PoseidonConfig<E::ScalarField>,
}


// Implementing the ConstraintSynthesizer trait for our circuit.
// This makes HashToPrimeHashCircuit a valid SNARK circuit that LegoGroth16 can use.
// ConstraintSynthesizer<E::ScalarField> means all constraints work over the scalar field of curve E.
// E::ScalarField example: for BLS12-381, Fr is a ~255-bit prime field.
// This trait requires ONE method: generate_constraints()
// LegoGroth16 calls generate_constraints() during both setup (None values) and proving (Some values).
impl<E: Pairing, P: HashToPrimeHashParameters> ConstraintSynthesizer<E::ScalarField>
    for HashToPrimeHashCircuit<E, P>
{
        // The main circuit function — generates all R1CS constraints.
        // This is called by LegoGroth16 during both setup and proving.
        //
        // self (not &self) — the circuit is CONSUMED, not borrowed.
        // arkworks requires ownership because the circuit values are moved
        // into the constraint system during constraint generation.
        //
        // cs: ConstraintSystemRef<E::ScalarField> — the constraint system we add constraints to.
        // Think of it as a blank sheet where we write our equations.
        // E::ScalarField is the field all equations work over (scalar field of BLS12-381).
        //
        // Returns Ok(()) if all constraints were added successfully,
        // or Err(SynthesisError) if something went wrong.
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        // IMPORTANT: Allocate e as the FIRST Witness variable.
        // Dock's legogroth16 commits to the first commit_witness_count witnesses.
        // This must come BEFORE all other variable allocations.
        let result = FpVar::new_variable(
            ark_relations::ns!(cs, "prime"),
            || self.prime.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;
        // Allocate the secret value u as a PRIVATE witness variable in the circuit. FpVar is a field element variable INSIDE the circuit, not a regular Rust number. ark_relations::ns!(cs, "alloc value") creates a namespace with a debug label. || self.value.get() is a closure that provides the value — during setup it's None (circuit learns shape only), during proving it's Some(u) (real value). AllocationMode::Witness means prover knows this, verifier does NOT. The ? propagates any allocation error.
        let f = FpVar::new_variable(ark_relations::ns!(cs, "alloc value"), || self.value.get(), AllocationMode::Witness)?;
        
        // Create an empty vector to hold the individual bits of counter j.
        // j is the counter that increments until hash(u, j) produces a prime.
        // The bits will be allocated as Boolean circuit variables in the loop below.
        // vec![] is a Rust macro that creates an empty Vec (like std::vector in C++).
        let mut index_bits = vec![];

        // Compute how many bits the counter j needs.
        // P is HashToPrimeHashParameters — it provides the index_bit_length function.
        // Example: security_level=128, MESSAGE_SIZE=254 → log2(128*254) ≈ 15 bits → j can range from 0 to 32768.
        // This determines how many Boolean witnesses we allocate for j in the circuit.
        let index_bit_length = P::index_bit_length(self.security_level);

        // Safety check: j must fit in u64 (64 bits). In practice ~15 bits, so never triggers.
        if index_bit_length > 64 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Allocate each bit of counter j as a separate Boolean witness variable in the circuit.
        // Loops from i=0 to index_bit_length (e.g., 15 times for 15-bit j).
        // Bits are stored in little-endian order (LSB first).
        // Each Boolean is a circuit variable constrained to 0 or 1, not a Rust bool.
        for i in 0..index_bit_length {
            index_bits.push(Boolean::new_variable(
                // Debug label for this variable in the constraint system
                ark_relations::ns!(cs, "alloc bit"),
                // Closure that extracts the i-th bit of j using bitwise mask and AND
                || {
                    // During setup: no value, just learning circuit shape
                    if self.index.is_none() {
                        Err(SynthesisError::AssignmentMissing)
                    } else {
                        // During proving: extract bit i from j
                        // Example: j=6 (110), i=1 → mask=010, (010 & 110)=010, 010==010 → true
                        let mask = 1u64 << i;
                        Ok((mask & self.index.unwrap()) == mask)
                    }
                },
                // j is private — verifier doesn't know which counter value produced the prime
                AllocationMode::Witness,
            )?);
        }


        // Convert the witness variable f (which holds u) from a field element to individual Boolean circuit wires in big-endian order (MSB first).
        // f is an FpVar (~254 bits), so this produces ~254 Boolean variables.
        // This conversion adds ~254 constraints to the circuit (each bit must be 0 or 1, and they must reconstruct f).
        // These bits will be concatenated with index_bits (j) and fed to Blake2s.
        // Note: this is the expensive step that Poseidon would eliminate — Poseidon takes field elements directly.
        let bits = f.to_bits_be()?;
        
        // Concatenate index bits (j) and value bits (u) to form the Blake2s input: H(u, j) from the paper (Section 4.1).
        // index_bits → ~15 bits of counter j (little-endian).
        // &bits[255-254..] = &bits[1..] → skip the leading 0 (from 255-bit field representation), take the 254 meaningful bits of u.
        // .concat() joins them into one Vec: [j_bits || u_bits] → ~269 Boolean circuit wires ready for Blake2s.
        let bits_to_hash: Vec<Boolean<E::ScalarField>> = [
            index_bits.as_slice(),
            &bits[<E::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize - P::MESSAGE_SIZE as usize..],
        ]
        .concat();

        // Blake2s operates on bytes (8 bits). Total bits must be a multiple of 8.
        // If not, pad with zero bits at the front (MSB side) — doesn't change the value.
        // Example: 269 bits → 269 % 8 = 5 → pad 3 zero bits → 272 bits = 34 bytes.
        // Boolean::constant(false) is a fixed 0 in the circuit — not a variable, no constraints added.
        let bits_to_hash_padded = if bits_to_hash.len() % 8 != 0 {
            let padding_length = 8 - bits_to_hash.len() % 8;
            // Prepend zero bits and concatenate with original bits.
            // &vec![...][..] and .as_slice() both convert Vec to a read-only slice (&).
            // .concat() reads both slices and creates a new Vec joining them.
            [
                &vec![Boolean::constant(false); padding_length][..],
                bits_to_hash.as_slice(),
            ]
            .concat()
        } else {
            // Already a multiple of 8 — no padding needed
            bits_to_hash
        };

        // Run Blake2s hash INSIDE the circuit on the padded bits.
        // This is the CIRCUIT version of Blake2s — adds ~25,000 R1CS constraints.
        // Input: ~272 Boolean circuit wires. Output: 8 UInt32 values (256 bits total).
        let hash_result = evaluate_blake2s(&bits_to_hash_padded)?;

        // Convert hash output from 8 UInt32 chunks into 256 individual Boolean bits.
        // .into_iter() → iterate over each UInt32 chunk
        // .map(|n| n.to_bits_le()) → closure that converts each UInt32 into 32 Boolean bits (little-endian)
        // .flatten() → join nested [[32 bits], [32 bits], ...] into one flat stream [256 bits]
        // .collect() → gather all 256 Boolean bits into one Vec
        let hash_bits = hash_result
            .into_iter()
            .map(|n| n.to_bits_le())
            .flatten()
            .collect::<Vec<Boolean<E::ScalarField>>>();

        // Take only the first (µ - 1) bits from the 256-bit hash output.
        // µ = required_bit_size (e.g., 252). Always less than field size (~255) to ensure result fits.
        // Takes 251 bits here. Next step prepends a 1 bit → total µ bits.
        // This ensures e = 1|H(u,j) ∈ [2^(µ-1), 2^µ) as the paper requires (Section 4.1).
        let hash_bits = hash_bits
            .into_iter()
            .take((self.required_bit_size - 1) as usize)
            .collect::<Vec<_>>();

        // Prepend a 1 bit to the (µ-1) hash bits → "1|H(u,j)" from paper Section 4.1. Guarantees e ∈ [2^(µ-1), 2^µ).
        let hash_bits = [&[Boolean::constant(true)][..], &hash_bits].concat();

        // Allocate the hash-to-prime result e as a circuit Input variable.
        // In LegoGroth16, Input does NOT mean public — e is still hidden.
        // LegoGroth16 includes Input variables in link_d = base_one + e·g + r_q·h.
        // base_one is a structural artifact from R1CS wire 0 (always 1).
        // Verifier subtracts base_one, then checks: (link_d - base_one) == c_e_q.
        // So e is linked to external c_e_q but never revealed.
        // The closure reconstructs e as a field element from the µ Boolean hash bits.
        
        // Convert the result (e as field element FpVar) back into individual Boolean circuit wires (big-endian).
        // This produces ~255 bits (full field element size).
        // These bits will be compared against hash_bits to enforce that result actually equals 1|H(u,j).
        // This is the CONSTRAINT part — so far we just DECLARED result, now we'll ENFORCE it matches the hash output.
        let result_bits = result.to_bits_be()?;
        
        // Enforce that the leading bits of result are all 0.
        // result_bits has ~255 bits (full field element, big-endian).
        // required_bit_size = µ (e.g., 252).
        // 255 - 252 = 3 → first 3 bits MUST be 0.
        // This constrains e to fit within µ bits: e < 2^µ.
        // Without this, a cheating prover could put a larger value in result
        // that has the same lower bits but different leading bits.
        // .take(255 - 252 = 3) → iterate over just the first 3 bits
        // .enforce_equal(&Boolean::constant(false)) → each must be 0
        for b in result_bits
            .iter()
            .take(<E::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize - self.required_bit_size as usize)
        {
            b.enforce_equal(
                &Boolean::constant(false),
            )?;
        }



        // Enforce that the last µ bits of result match hash_bits exactly, bit by bit.
        // This is the CORE CONSTRAINT — "the value e in result actually equals 1|H(u,j)".
        //
        // hash_bits → µ bits: [1, h0, h1, ..., h_(µ-2)]  (the hash output with prepended 1)
        //
        // result_bits → 255 bits: [0, 0, 0, r3, r4, ..., r254]  (full field element)
        //   .skip(255 - 252 = 3) → [r3, r4, ..., r254]  (skip leading zeros, take last µ bits)
        //
        // .zip() pairs them up one-to-one:
        //   (hash_bits[0], result_bits[3])
        //   (hash_bits[1], result_bits[4])
        //   ...
        //   (hash_bits[µ-1], result_bits[254])
        //
        // enforce_equal → each pair MUST be equal. This is the actual R1CS constraint.
        // Without this, prover could put any value in result and claim it's the hash output.
        for (h, r) in hash_bits
            .iter()
            // .zip() combines two iterators into pairs: (element_from_first, element_from_second)
            .zip(
                result_bits
                    .iter()
                    // Skip the leading bits we already enforced to be 0
                    .skip(<E::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize - self.required_bit_size as usize),
            )
        {
            // h = one bit from hash_bits (the actual hash output)
            // r = one bit from result_bits (the declared result)
            // enforce_equal adds an R1CS constraint: h == r
            h.enforce_equal(&r)?;
        }
        Ok(())
    }
}

/// ConstraintSynthesizer implementation for the Poseidon-based hash-to-prime circuit.
/// This is the circuit that LegoGroth16 uses — called during both setup (None values) and proving (Some values).
/// E::ScalarField: Absorb is required because Poseidon sponge needs field elements to implement Absorb trait.
impl<E: Pairing<ScalarField = ark_bls12_381::Fr>> ConstraintSynthesizer<E::ScalarField>
    for PoseidonHashToPrimeCircuit<E>
where
    E::ScalarField: Absorb,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        // FIRST: Allocate e as the first Witness variable.
        let result = FpVar::new_variable(
            ark_relations::ns!(cs, "prime"),
            || self.prime.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        // Allocate u_x, u_y, j as private witnesses
        let u_x_var = FpVar::new_variable(
            ark_relations::ns!(cs, "u_x"),
            || self.u_x.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;
        let u_y_var = FpVar::new_variable(
            ark_relations::ns!(cs, "u_y"),
            || self.u_y.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;
        let j_var = FpVar::new_variable(
            ark_relations::ns!(cs, "index"),
            || self.index.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        // ============================================================
        // Step 1: Poseidon hash-to-prime
        // ============================================================
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);
        sponge.absorb(&u_x_var)?;
        sponge.absorb(&u_y_var)?;
        sponge.absorb(&j_var)?;
        let hash_output = sponge.squeeze_field_elements(1)?;
        let h = hash_output[0].clone();

        let h_bits = h.to_bits_be()?;
        let skip = <E::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize - (self.required_bit_size as usize - 1);
        let bottom_bits: Vec<Boolean<E::ScalarField>> = h_bits[skip..].to_vec();

        let mut r_var = FpVar::Constant(E::ScalarField::from(0u64));
        let mut bit_power = E::ScalarField::from(1u64);
        for bit in bottom_bits.iter().rev() {
            r_var += FpVar::from(bit.clone()) * FpVar::Constant(bit_power);
            bit_power += bit_power;
        }

        let leading_one = {
            let mut v = E::ScalarField::from(1u64);
            for _ in 0..(self.required_bit_size - 1) {
                v += v;
            }
            v
        };
        let e_var = &r_var + &FpVar::Constant(leading_one);
        result.enforce_equal(&e_var)?;

        let after_h2p = cs.num_constraints();
        println!("Step 1 — Hash-to-prime: {} constraints", after_h2p);

        // ============================================================
        // Step 2: EC Diffie-Hellman
        // ============================================================
        let e_sec_var = FpVar::new_variable(
            ark_relations::ns!(cs, "e_sec"),
            || self.e_sec.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        let pubkey_var = JubJubVar::new_variable_omit_prime_order_check(
            ark_relations::ns!(cs, "pubkey"),
            || {
                match (self.u_x, self.u_y) {
                    (Some(x), Some(y)) => Ok(ark_ed_on_bls12_381::EdwardsAffine::new(x, y).into()),
                    _ => Err(SynthesisError::AssignmentMissing),
                }
            },
            AllocationMode::Witness,
        )?;

        pubkey_var.x.enforce_equal(&u_x_var)?;
        pubkey_var.y.enforce_equal(&u_y_var)?;

        let e_sec_bits = e_sec_var.to_bits_le()?;
        let shared_key_var = pubkey_var.scalar_mul_le(e_sec_bits.iter())?;

        let after_ecdh = cs.num_constraints();
        println!("Step 2 — ECDH:          {} constraints (delta: {})", after_ecdh, after_ecdh - after_h2p);

        // ============================================================
        // Step 3: KDF
        // ============================================================
        let salt_var = FpVar::Constant(self.salt);
        let info_var = FpVar::Constant(self.info);

        let mut kdf_sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);
        kdf_sponge.absorb(&salt_var)?;
        kdf_sponge.absorb(&shared_key_var.x)?;
        kdf_sponge.absorb(&shared_key_var.y)?;
        kdf_sponge.absorb(&info_var)?;
        let kdf_output = kdf_sponge.squeeze_field_elements(1)?;
        let k_pos = kdf_output[0].clone();

        let after_kdf = cs.num_constraints();
        println!("Step 3 — KDF:           {} constraints (delta: {})", after_kdf, after_kdf - after_ecdh);

        // ============================================================
        // Step 4: Byte Packing
        // ============================================================
        let max_bytes = 31;
        let mut m_var = FpVar::Constant(E::ScalarField::from(0u64));
        let mut power = E::ScalarField::from(1u64);

        for i in 0..max_bytes {
            let mut byte_bits = Vec::new();
            for j in 0..8u8 {
                byte_bits.push(Boolean::new_variable(
                    ark_relations::ns!(cs, "byte_bit"),
                    || {
                        match &self.email_bytes {
                            Some(bytes) if i < bytes.len() => {
                                Ok(((bytes[i] >> j) & 1) == 1)
                            },
                            Some(_) => Ok(false),
                            None => Err(SynthesisError::AssignmentMissing),
                        }
                    },
                    AllocationMode::Witness,
                )?);
            }

            let mut byte_var = FpVar::Constant(E::ScalarField::from(0u64));
            let mut two_power = E::ScalarField::from(1u64);
            for bit in byte_bits.iter() {
                byte_var += FpVar::from(bit.clone()) * FpVar::Constant(two_power);
                two_power += two_power;
            }

            m_var += &byte_var * FpVar::Constant(power);
            power *= E::ScalarField::from(256u64);
        }

        let after_pack = cs.num_constraints();
        println!("Step 4 — Byte packing:  {} constraints (delta: {})", after_pack, after_pack - after_kdf);

        // ============================================================
        // Step 5: Keystream
        // ============================================================
        let nc_var = FpVar::new_variable(
            ark_relations::ns!(cs, "nc"),
            || self.nc.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Input,
        )?;

        let mut enc_sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);
        enc_sponge.absorb(&salt_var)?;
        enc_sponge.absorb(&k_pos)?;
        enc_sponge.absorb(&nc_var)?;
        let enc_output = enc_sponge.squeeze_field_elements(1)?;
        let keystream = enc_output[0].clone();

        let after_ks = cs.num_constraints();
        println!("Step 5 — Keystream:     {} constraints (delta: {})", after_ks, after_ks - after_pack);

        // ============================================================
        // Step 6: Encryption
        // ============================================================
        let ciphertext = &m_var + &keystream;

        let c_pub = FpVar::new_variable(
            ark_relations::ns!(cs, "ciphertext"),
            || ciphertext.value(),
            AllocationMode::Input,
        )?;
        ciphertext.enforce_equal(&c_pub)?;

        let after_enc = cs.num_constraints();
        println!("Step 6 — Encryption:    {} constraints (delta: {})", after_enc, after_enc - after_ks);
        println!("Total constraints:      {}", after_enc);

        Ok(())
    }
}


// The hash-to-prime protocol struct. Holds the CRS and provides prove/verify/hash_to_prime methods.
// E: Pairing — the elliptic curve (BLS12-381). Needed for LegoGroth16 (pairing-based SNARK).
// P: HashToPrimeHashParameters — configuration (MESSAGE_SIZE, index_bit_length).
pub struct Protocol<E: Pairing, P: HashToPrimeHashParameters> {
    // Public parameters for hash-to-prime sub-protocol.
    // Contains: security parameters, Pedersen generators (g, h), and LegoGroth16 proving key (which includes verification key).
    // In production, prover uses full proving key, verifier extracts .vk (verification key) from it.
    pub crs: CRSHashToPrime<E::G1, Self>,
    // PhantomData — P is used in methods (MESSAGE_SIZE, index_bit_length) but not stored in fields.
    parameters_type: std::marker::PhantomData<P>,
}


//   "let me declare E and P"                       //  "I'm implementing this trait, working in E's G1 group"
impl<E: Pairing, P: HashToPrimeHashParameters> HashToPrimeProtocol<E::G1>
    //  "for this struct, which uses both E and P"
    for Protocol<E, P>
{
    // The proof type for this implementation is a LegoGroth16 proof.
    // Contains (A, B, C, link_d) — the standard Groth16 elements plus the linking commitment.
    type Proof = legogroth16::ProofWithLink<E>;
    type Parameters = legogroth16::ProvingKeyWithLink<E>;
    // The parameters type is a LegoGroth16 proving key (which includes verification key inside).
    // Generated during trusted setup. Used by prover to create proofs, verifier extracts .vk from it.
    //type Parameters = legogroth16::ProvingKey<E>;

    // Constructor — creates a Protocol instance from the CRS (public parameters).
    // Borrows the CRS, clones it into an owned copy, and wraps it in the Protocol struct.
    // Required by the HashToPrimeProtocol trait — every implementation must provide this.
    fn from_crs(crs: &CRSHashToPrime<E::G1, Self>) -> Protocol<E, P> {
        Protocol {
            crs: (*crs).clone(),
            parameters_type: std::marker::PhantomData,
        }
    }
    // Setup (trusted setup) — generates the LegoGroth16 proving key for the hash-to-prime circuit.
    // Called ONCE before any proving/verifying. Corresponds to KeyGen in the paper.
    // <R: Rng> — generic over any random number generator (only needed during setup, not other methods).
    // rng — mutable borrow, consumes randomness for key generation.
    // pedersen_commitment_parameters — generators (g, h) from Gq, injected into LegoGroth16 as link_bases
    //   so that link_d uses the SAME g and h as external commitment c_e_q.
    // parameters — security parameters (security_level, hash_to_prime_bits µ, etc.)
    // Returns LegoGroth16 ProvingKey (Self::Parameters) on success, SetupError on failure.
    fn setup<R: Rng>(
        rng: &mut R,
        pedersen_commitment_parameters: &PedersenCommitment<E::G1>,
        parameters: &Parameters,
    ) -> Result<Self::Parameters, SetupError> {
        // Create the circuit with NO actual values (None).
        // This is setup — we don't know u or j yet.
        // LegoGroth16 needs the circuit to learn its SHAPE:
        //   "how many variables? how many constraints? how are they connected?"
        // The shape is the same regardless of actual values.
        // During proving later, a NEW circuit will be created with Some(u) and Some(j).
        let c = HashToPrimeHashCircuit::<E, P> {
            security_level: parameters.security_level,
            required_bit_size: parameters.hash_to_prime_bits,
            value: None,     // u unknown during setup
            index: None,     // j unknown during setup
            prime: None,
            parameters_type: std::marker::PhantomData,
        };
        // Generate a random point in G1 — this becomes base_one (link_bases[0]) in LegoGroth16.
        // This is the R1CS wire 0 constant we discussed earlier.
        // link_d = 1·base_one + e·g + r_q·h
        //              ↑
        //          this random point
        // let base_one = E::G1::rand(rng);
        // // Build the vector of Pedersen bases for LegoGroth16's linking mechanism.
        // // These bases define what link_d looks like:
        // //   link_d = 1·base_one + e·g + r_q·h
        // //
        // //   pedersen_bases[0] = base_one → multiplied by wire 0 (always 1)
        // //   pedersen_bases[1] = g        → multiplied by e (the prime)
        // //   pedersen_bases[2] = h        → multiplied by r_q (the blinding randomness)
        // //
        // // g and h are the SAME generators used in the external Pedersen commitment c_e_q = e·g + r_q·h.
        // // This is the KEY — by using the same g and h, the verifier can check:
        // //   link_d - base_one == c_e_q
        // //   (1·base_one + e·g + r_q·h) - base_one == e·g + r_q·h == c_e_q  ✓
        // let pedersen_bases = vec![
        //     base_one,
        //     pedersen_commitment_parameters.g,
        //     pedersen_commitment_parameters.h,
        // ];
        // // Run LegoGroth16 trusted setup — generates the proving key (which includes verification key).
        // // Toxic waste is generated internally and must be destroyed after this call.
        // Ok(legogroth16::generate_random_parameters(
        //     // The circuit with None values — LegoGroth16 learns the circuit SHAPE (variables, constraints).
        //     c,
        //     // Convert the Pedersen bases [base_one, g, h] from Projective (X,Y,Z) to Affine (x,y) representation.
        //     // Affine is smaller and is what LegoGroth16 setup expects.
        //     // These become link_bases inside the proving key: link_d = 1·base_one + e·g + r_q·h.
        //     // &pedersen_bases
        //     //     .into_iter()
        //     //     .map(|p| p.into_affine())
        //     //     .collect::<Vec<_>>(),
        //     3,
        //     // Randomness source for key generation (generates toxic waste internally).
        //     rng,
        // // Inner ? propagates error from generate_random_parameters.
        // // Outer Ok() wraps the result to match the function's return type.
        // )?)
        let link_gens = legogroth16::data_structures::LinkPublicGenerators::<E> {
            pedersen_gens: vec![
                pedersen_commitment_parameters.g.into_affine(),
                pedersen_commitment_parameters.h.into_affine(),
            ],
            g1: E::G1::rand(rng).into_affine(),
            g2: E::G2::rand(rng).into_affine(),
        };
        Ok(legogroth16::generate_random_parameters_incl_cp_link(
            c,
            link_gens,
            1,  // commit_witness_count: commit to 1 witness (e)
            rng,
        )?)
    }


    // Create a LegoGroth16 proof that e = 1|H(u, j) — the hash-to-prime was computed correctly.
    // &self — borrows the Protocol (has the CRS with proving key).
    // verifier_channel — Fiat-Shamir channel, mutable because sending changes its state.
    // rng — randomness for proof generation, mutable because generating randomness changes state.
    // _ — Statement (c_e_q) not used by prover — LegoGroth16's link_d handles the linking.
    // witness — the secret: witness.e is actually u (original value, confusingly named), r_q is Pedersen blinding.
    // Returns Ok(()) on success or ProofError if anything fails.
    fn prove<R: Rng, C: HashToPrimeVerifierChannel<E::G1, Self>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<E::G1>,
        witness: &Witness,
    ) -> Result<(), ProofError> {
        // Step 1 (native): find the counter j by hashing u until a prime is found.
        // self.hash_to_prime tries hash(u, j=0), hash(u, j=1), ... until result is prime.
        // Returns (e, j) but we only keep j — e is redundant as the circuit derives it from u and j.
        // witness.e is actually u (the original value, confusingly named in the Witness struct).
        let (hashed_e, index) = self.hash_to_prime(&witness.e, None)?;
        let prime_field = integer_to_bigint_mod_q::<E::G1>(&hashed_e)?;

        
        // Step 2: Build the circuit with REAL values (unlike setup which used None).
        // This circuit will be passed to LegoGroth16 to create the proof.
        let c = HashToPrimeHashCircuit::<E, P> {
            // Security parameter (e.g., 128)
            security_level: self.crs.parameters.security_level,
            // µ — how many bits the output prime must be
            required_bit_size: self.crs.parameters.hash_to_prime_bits,
            // The secret input u, converted from Integer (rug) to field element (arkworks).
            // witness.e is actually u (confusingly named).
            // .clone() because we borrow witness, can't move out of it.
            // integer_to_bigint_mod_q converts: Integer → E::ScalarField (field element mod q)
            // Some() because this is proving — we have real values (unlike setup's None).
            value: Some(integer_to_bigint_mod_q::<E::G1>(
                &witness.e.clone(),
            )?),
            // The counter j found in Step 1 by native hash_to_prime.
            // Some() because we know j now.
            index: Some(index),
            prime: Some(prime_field),
            parameters_type: std::marker::PhantomData,
        };

        // Random blinding for Groth16's A, B, C — inherited from standard Groth16, makes the proof zero-knowledge.
        // Fresh random value every time — like a nonce, ensures same witness produces different proofs.
        let v = E::ScalarField::rand(rng);
        // Pedersen blinding for LegoGroth16's link_d — added by LegoGroth16, makes the commitment hiding.
        // Converts r_q from rug Integer to arkworks field element.
        // MUST be the same r_q used in the external c_e_q = e·g + r_q·h, otherwise verification fails.
        let link_v = integer_to_bigint_mod_q::<E::G1>(&witness.r_q.clone())?;
        
        // Create the LegoGroth16 proof — this is where everything comes together.
        // Internally: runs generate_constraints with real values, computes A, B, C, and link_d.
        // ::<E, _, _> — E is the curve (BLS12-381), the two _ let Rust infer the circuit and RNG types.
        // let proof = legogroth16::create_random_proof::<E, _, _>(
        //     // The circuit with real values: u (value) and j (index).
        //     // LegoGroth16 calls c.generate_constraints() → all constraints run with real data.
        //     // Internally: hash(u, j) → e → e becomes AllocationMode::Input → goes into link_d.
        //     c,
        //     // Groth16 blinding (fresh random) — randomizes A, B, C so proof is zero-knowledge.
        //     v,
        //     // Pedersen blinding for link_d — MUST be same r_q used in external c_e_q.
        //     // link_d = base_one + e·g + link_v·h
        //     //link_v,
        //     // The proving key from trusted setup — contains circuit encodings and link_bases.
        //     &self.crs.hash_to_prime_parameters,
        //     // Randomness source for internal proof computations.
        //     rng,
        // // ? propagates any error (constraint unsatisfied, bad parameters, etc.)
        // )?;
        let proof = legogroth16::create_random_proof_incl_cp_link::<E, _, _>(
            c,
            v,
            link_v,
            &self.crs.hash_to_prime_parameters,
            rng,
        )?;
        verifier_channel.send_proof(&proof)?;
        Ok(())
    }

    // Verify the LegoGroth16 proof that e = 1|H(u, j) was computed correctly.
    // Two checks: (1) Groth16 pairing equation holds, (2) link_d matches external c_e_q.
    // &self — borrows the Protocol (has the CRS with verification key).
    // prover_channel — Fiat-Shamir channel for receiving the proof from the prover.
    // statement — contains c_e_q (the external Pedersen commitment to e).
    //   This is what link_d gets checked against.
    //   Unlike prove(), the verifier DOES use the statement.
    // Returns Ok(()) if proof is valid, Err(VerificationFailed) if not.
    fn verify<C: HashToPrimeProverChannel<E::G1, Self>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<E::G1>,
    ) -> Result<(), VerificationError> {
        // // Receive the LegoGroth16 proof (A, B, C, link_d) from the prover through the Fiat-Shamir channel.
        // let proof = prover_channel.receive_proof()?;

        // // Extract and prepare the verification key from the proving key stored in the CRS.
        // // .vk accesses the VerifyingKey inside the ProvingKey.
        // // prepare_verifying_key precomputes pairing values for faster verification.
        // let pvk = legogroth16::prepare_verifying_key(&self.crs.hash_to_prime_parameters.vk);

        // // Check 1: Groth16 pairing equation — e(A, B) = e(α, β) · e(C, δ) · e(D, γ)
        // // This ensures the circuit constraints were satisfied AND link_d is consistent with A, B, C.
        // // If the prover faked link_d, the pairing equation fails because of the secret γ from trusted setup.
        // legogroth16::verify_proof(&pvk, &proof, &[])?;

        // // Check 2: link_d must match the external Pedersen commitment c_e_q.
        // // link_d = base_one + e·g + r_q·h  (computed by LegoGroth16 during proving)
        // // Subtract base_one (the R1CS wire 0 constant) to get: e·g + r_q·h
        // // .into_projective() converts from Affine to Projective for the subtraction.
        // // link_bases[0] is base_one from the verification key.
        // let proof_d = proof.d.into_group();
        // let base_one = self.crs.hash_to_prime_parameters.vk.commit_witness_count;

        // // Compare: (link_d - base_one) must equal c_e_q
        // // link_d - base_one = e·g + r_q·h (from inside the SNARK)
        // // c_e_q = e·g + r_q·h (from outside, the membership protocol)
        // // If same e and r_q → they match → proof is valid
        // // If different → don't match → prover cheated
        // if statement.c_e_q != proof_d {
        //     return Err(VerificationError::VerificationFailed);
        // }
        let proof = prover_channel.receive_proof()?;
        let pvk = legogroth16::prepare_verifying_key(&self.crs.hash_to_prime_parameters.vk.groth16_vk);
        legogroth16::verify_proof_incl_cp_link(
            &pvk,
            &self.crs.hash_to_prime_parameters.vk,
            &proof,
            &[],
        )?;
        if statement.c_e_q != proof.link_d.into_group() {
            return Err(VerificationError::VerificationFailed);
        }
        Ok(())
    }

    // Native hash-to-prime function — runs on the CPU, NOT inside a SNARK circuit.
    // Searches for a counter j such that 1|Blake2s(u, j) is a prime number.
    // Tries j = 0, 1, 2, ... until a prime is found or all attempts exhausted.
    // &self — borrows Protocol (needs CRS parameters like security_level, hash_to_prime_bits).
    // e — confusingly named, this is actually u (the original value), not the prime.
    // Returns (prime_e, index_j) on success — the prime found and which j produced it.
    // Returns HashToPrimeError if no prime found after all 2^index_bit_length attempts.
    fn hash_to_prime(&self, e: &Integer, _key_coords: Option<(&Integer, &Integer)>) -> Result<(Integer, u64), HashToPrimeError> {
        // How many bits the counter j needs. Example: security_level=128, MESSAGE_SIZE=254 → ~15 bits.
        let index_bit_length = P::index_bit_length(self.crs.parameters.security_level);

        // Convert u from rug Integer to arkworks field element (mod q).
        // Again, unnecessary field conversion — u is just input to a hash function.
        let value = integer_to_bigint_mod_q::<E::G1>(e)?;

        // Compute the total number of bits in the arkworks BigInt representation.
        // E::ScalarField::one() → the field element 1
        // .neg() → -1 mod q = q - 1 (the largest value in the field)
        // .into_bigint() → convert to raw BigInt
        // .num_bits() → how many bits needed to represent q - 1 (e.g., 255)
        // + 63) / 64 → round UP to nearest multiple of 64 (because BigInt uses 64-bit limbs)
        // * 64 → total bits in the padded representation (e.g., 256)
        // This accounts for the fact that arkworks BigInt pads to 64-bit boundaries.
        let bigint_bits = 64 * ((E::ScalarField::one().neg().into_bigint().num_bits() + 63) / 64);

        // How many leading bits to skip to get MESSAGE_SIZE meaningful bits.
        // Example: bigint_bits=256, MESSAGE_SIZE=254 → skip first 2 bits.
        let bits_to_skip = bigint_bits as usize - P::MESSAGE_SIZE as usize;

        // Convert the field element to its raw bit representation in big-endian order.
        // This gives bigint_bits number of bits (e.g., 256) including leading zeros.
        let value_raw_bits = value.into_bigint().to_bits_be();
        
        // Check that the leading bits (the ones we'll skip) are all 0.
        // If any leading bit is 1, it means u ≥ 2^MESSAGE_SIZE — too big to fit.
        // This is the guard that enforces the artificial 254-bit restriction from using FpVar.
        // If the authors had used raw Boolean bits, this check wouldn't be needed.
        // &value_raw_bits[..bits_to_skip] → the first 2 bits (for BLS12-381: 256 - 254 = 2).
        // *b dereferences the boolean — if true, the bit is 1, meaning value is too large.
        for b in &value_raw_bits[..bits_to_skip] {
            if *b {
                return Err(HashToPrimeError::ValueTooBig);
            }
        }

        let mut value_bits = value_raw_bits[bits_to_skip..].to_vec();
        // If value_bits is shorter than MESSAGE_SIZE, pad with leading zeros (false) at the front.
        // This can happen if u is a small number — e.g., u=5 (binary: 101) is only 3 bits
        // but MESSAGE_SIZE requires 254 bits → pad with 251 zeros in front.
        // vec![false; ...] creates a vector of zeros with the exact padding length needed.
        // [padding, value_bits].concat() joins them: [0, 0, ..., 0, 1, 0, 1] → 254 bits total.
        if value_bits.len() < P::MESSAGE_SIZE as usize {
            value_bits = [
                vec![false; P::MESSAGE_SIZE as usize - value_bits.len()],
                value_bits,
            ]
            .concat();
        }
        
        // Loop through all possible counter values j = 0, 1, 2, ..., (2^index_bit_length - 1).
        // This is the SEARCH — try each j until hash(u, j) produces a prime.
        // 1 << index_bit_length = 2^index_bit_length (left shift by index_bit_length positions).
        // Example: index_bit_length = 15 → 1 << 15 = 32768 → tries j from 0 to 32767.
        // 0.. means "from 0 up to (but not including)".
        for index in 0..1 << index_bit_length {
            let mut index_bits = vec![];
            for i in 0..index_bit_length {
                let mask = 1u64 << i;
                let bit = mask & index == mask;
                index_bits.push(bit);
            }
            let bits_to_hash = [index_bits.as_slice(), &value_bits].concat();
            let bits_to_hash_padded = if bits_to_hash.len() % 8 != 0 {
                let padding_length = 8 - bits_to_hash.len() % 8;
                [&vec![false; padding_length][..], bits_to_hash.as_slice()].concat()
            } else {
                bits_to_hash
            };
            let bits_big_endian = bits_to_hash_padded.into_iter().rev().collect::<Vec<_>>();
            let bytes_to_hash = bits_big_endian_to_bytes_big_endian(&bits_big_endian)
                .into_iter()
                .rev()
                .collect::<Vec<_>>();
            let mut hasher = Blake2s256::new();
            hasher.update(&bytes_to_hash);
            let hash = hasher.finalize();
            let hash_big_endian = hash.into_iter().rev().collect::<Vec<_>>();
            let hash_bits = [
                vec![true].as_slice(),
                bytes_big_endian_to_bits_big_endian(&hash_big_endian)
                    .into_iter()
                    .rev()
                    .take(self.crs.parameters.hash_to_prime_bits as usize - 1)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ]
            .concat();

            let element = E::ScalarField::from_bigint(<E::ScalarField as PrimeField>::BigInt::from_bits_be(&hash_bits)).unwrap();
            let integer = bigint_to_integer::<E::G1>(&element);
            // from the gmp documentation: "A composite number will be identified as a prime with an asymptotic probability of less than 4^(-reps)", so we choose reps = security_level/2
            let is_prime = integer.is_probably_prime(self.crs.parameters.security_level as u32 / 2);
            if is_prime == IsPrime::No {
                continue;
            }

            return Ok((integer, index));
        }

        Err(HashToPrimeError::CouldNotFindIndex)
    }
}


/// Generate Poseidon parameters for BLS12-381 scalar field.
/// In production, use published/audited parameters. This is for testing.
pub fn poseidon_config_for_test<F: PrimeField + Absorb>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 17;
    let rate = 2;
    let capacity = 1;
    let num_state = rate + capacity;
    let num_constants = (full_rounds + partial_rounds) * num_state;

    let mut constants = Vec::new();
    let mut current = F::from(42u64);
    for _ in 0..num_constants {
        current = current + current + F::one();
        constants.push(current);
    }

    let mut mds = vec![vec![F::zero(); num_state]; num_state];
    for i in 0..num_state {
        for j in 0..num_state {
            mds[i][j] = (F::from((i + j + 1) as u64)).inverse().unwrap_or(F::one());
        }
    }

    PoseidonConfig {
        full_rounds: full_rounds as usize,
        partial_rounds: partial_rounds as usize,
        alpha: alpha as u64,
        ark: constants.chunks(num_state).map(|c| c.to_vec()).collect(),
        mds,
        rate,
        capacity,
    }
}

/// Poseidon-based hash-to-prime protocol.
/// Replaces Blake2s with Poseidon for ~11x fewer constraints.
/// Takes (u_x, u_y) as JubJub public key coordinates.
pub struct PoseidonProtocol<E: Pairing<ScalarField = ark_bls12_381::Fr>> where E::ScalarField: Absorb {
    pub crs: CRSHashToPrime<E::G1, Self>,
    pub poseidon_config: PoseidonConfig<E::ScalarField>,
}

impl<E: Pairing<ScalarField = ark_bls12_381::Fr>> HashToPrimeProtocol<E::G1> for PoseidonProtocol<E>
where
    E::ScalarField: Absorb,
{
    type Proof = legogroth16::ProofWithLink<E>;
    type Parameters = legogroth16::ProvingKeyWithLink<E>;

    fn from_crs(crs: &CRSHashToPrime<E::G1, Self>) -> Self {
        PoseidonProtocol {
            crs: (*crs).clone(),
            poseidon_config: poseidon_config_for_test::<E::ScalarField>(),
        }
    }

    fn setup<R: Rng>(
        rng: &mut R,
        pedersen_commitment_parameters: &PedersenCommitment<E::G1>,
        parameters: &Parameters,
    ) -> Result<Self::Parameters, SetupError> {
        let poseidon_config = poseidon_config_for_test::<E::ScalarField>();
        let c = PoseidonHashToPrimeCircuit::<E> {
            required_bit_size: parameters.hash_to_prime_bits,
            u_x: None,
            u_y: None,
            index: None,
            prime: None,
            e_sec: None,
            salt: E::ScalarField::from(12345u64),
            info: E::ScalarField::from(67890u64),
            email_bytes: None,
            nc: None,
            poseidon_config,
        };
        let link_gens = legogroth16::data_structures::LinkPublicGenerators::<E> {
            pedersen_gens: vec![
                pedersen_commitment_parameters.g.into_affine(),
                pedersen_commitment_parameters.h.into_affine(),
            ],
            g1: E::G1::rand(rng).into_affine(),
            g2: E::G2::rand(rng).into_affine(),
        };
        Ok(legogroth16::generate_random_parameters_incl_cp_link(
            c, link_gens, 1, rng,
        )?)
    }

    fn prove<R: Rng, C: HashToPrimeVerifierChannel<E::G1, Self>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        statement: &Statement<E::G1>,
        witness: &Witness,
    ) -> Result<(), ProofError> {
        let (u_x_field, u_y_field) = match &witness.u_y {
            Some(uy) => (
                integer_to_bigint_mod_q::<E::G1>(&witness.e)?,
                integer_to_bigint_mod_q::<E::G1>(uy)?,
            ),
            None => {
                let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
                (gen.x, gen.y)
            }
        };

        // Hash-to-prime using the actual (u_x, u_y) coordinates
        let (hashed_e, index) = {
            let mut found = None;
            for idx in 0u64..1 << 16 {
                let mut native_sponge = PoseidonSponge::new(&self.poseidon_config);
                native_sponge.absorb(&u_x_field);
                native_sponge.absorb(&u_y_field);
                native_sponge.absorb(&E::ScalarField::from(idx));
                let native_h: E::ScalarField = native_sponge.squeeze_field_elements(1)[0];
                let h_bits = native_h.into_bigint().to_bits_be();
                let skip = h_bits.len() - (self.crs.parameters.hash_to_prime_bits as usize - 1);
                let hash_bits: Vec<bool> = [
                    vec![true].as_slice(),
                    &h_bits[skip..],
                ].concat();
                let element = E::ScalarField::from_bigint(
                    <E::ScalarField as PrimeField>::BigInt::from_bits_be(&hash_bits),
                ).unwrap();
                let integer = bigint_to_integer::<E::G1>(&element);
                let is_prime = integer.is_probably_prime(
                    self.crs.parameters.security_level as u32 / 2,
                );
                if is_prime == rug::integer::IsPrime::No {
                    continue;
                }
                found = Some((integer, idx));
                break;
            }
            found.ok_or(crate::protocols::hash_to_prime::HashToPrimeError::CouldNotFindIndex)?
        };
        let prime_field = integer_to_bigint_mod_q::<E::G1>(&hashed_e)?;

        // ============================================================
        // Native computation — prover computes everything outside circuit
        // ============================================================
        let salt = E::ScalarField::from(12345u64);
        let info = E::ScalarField::from(67890u64);
        let nc = statement.nc.unwrap_or(E::ScalarField::from(1u64));
        let email_bytes = witness.email_bytes.clone().unwrap_or_else(|| b"alice@example.com".to_vec());

        // EC DH: (x, y) = E_sec · (u_x, u_y)
        let e_sec_field = witness.e_sec.unwrap_or_else(|| E::ScalarField::rand(rng));
        let pubkey = ark_ed_on_bls12_381::EdwardsAffine::new(u_x_field, u_y_field);
        let shared_key = pubkey.mul_bigint(e_sec_field.into_bigint());
        let shared_affine = shared_key.into_affine();
        let shared_x = shared_affine.x;
        let shared_y = shared_affine.y;

        // KDF: K_pos = Poseidon(salt, x, y, info)
        let mut kdf_sponge = PoseidonSponge::new(&self.poseidon_config);
        kdf_sponge.absorb(&salt);
        kdf_sponge.absorb(&shared_x);
        kdf_sponge.absorb(&shared_y);
        kdf_sponge.absorb(&info);
        let k_pos: E::ScalarField = kdf_sponge.squeeze_field_elements(1)[0];

        // Byte packing: m = Σ b_i · 256^i
        let mut m_native = E::ScalarField::from(0u64);
        let mut power = E::ScalarField::from(1u64);
        for i in 0..31usize {
            let byte_val = if i < email_bytes.len() {
                E::ScalarField::from(email_bytes[i] as u64)
            } else {
                E::ScalarField::from(0u64)
            };
            m_native += byte_val * power;
            power *= E::ScalarField::from(256u64);
        }

        // Keystream: S = Poseidon(salt, K_pos, nc)
        let mut enc_sponge = PoseidonSponge::new(&self.poseidon_config);
        enc_sponge.absorb(&salt);
        enc_sponge.absorb(&k_pos);
        enc_sponge.absorb(&nc);
        let keystream: E::ScalarField = enc_sponge.squeeze_field_elements(1)[0];

        // Encryption: C = m + S
        let ciphertext_native = m_native + keystream;

        // ============================================================
        // Build circuit with all native values as witnesses
        // ============================================================
        let c = PoseidonHashToPrimeCircuit::<E> {
            required_bit_size: self.crs.parameters.hash_to_prime_bits,
            u_x: Some(u_x_field),
            u_y: Some(u_y_field),
            index: Some(E::ScalarField::from(index)),
            prime: Some(prime_field),
            e_sec: Some(e_sec_field),
            salt,
            info,
            email_bytes: Some(email_bytes),
            nc: Some(nc),
            poseidon_config: self.poseidon_config.clone(),
        };

        let v = E::ScalarField::rand(rng);
        let link_v = integer_to_bigint_mod_q::<E::G1>(&witness.r_q.clone())?;

        let proof = legogroth16::create_random_proof_incl_cp_link::<E, _, _>(
            c, v, link_v,
            &self.crs.hash_to_prime_parameters,
            rng,
        )?;
        verifier_channel.send_proof(&proof)?;
        Ok(())
    }

    fn verify<C: HashToPrimeProverChannel<E::G1, Self>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<E::G1>,
    ) -> Result<(), VerificationError> {
        let proof = prover_channel.receive_proof()?;
        let pvk = legogroth16::prepare_verifying_key(
            &self.crs.hash_to_prime_parameters.vk.groth16_vk,
        );
        let mut public_inputs: Vec<E::ScalarField> = Vec::new();
        if let Some(nc_val) = statement.nc {
            public_inputs.push(nc_val);
        }
        if let Some(c_val) = statement.ciphertext {
            public_inputs.push(c_val);
        }
        legogroth16::verify_proof_incl_cp_link(
            &pvk,
            &self.crs.hash_to_prime_parameters.vk,
            &proof,
            public_inputs.as_slice(),
        )?;
        if statement.c_e_q != proof.link_d.into_group() {
            return Err(VerificationError::VerificationFailed);
        }
        Ok(())
    }

    fn hash_to_prime(&self, e: &Integer, key_coords: Option<(&Integer, &Integer)>) -> Result<(Integer, u64), HashToPrimeError> {
        let (u_x, u_y) = match key_coords {
            Some((kx, ky)) => (
                crate::utils::integer_to_bigint_mod_q::<E::G1>(kx).unwrap(),
                crate::utils::integer_to_bigint_mod_q::<E::G1>(ky).unwrap(),
            ),
            None => {
                let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
                (gen.x, gen.y)
            }
        };

        for index in 0u64..1 << 16 {
            let mut native_sponge = PoseidonSponge::new(&self.poseidon_config);
            native_sponge.absorb(&u_x);
            native_sponge.absorb(&u_y);
            native_sponge.absorb(&E::ScalarField::from(index));
            let native_h: E::ScalarField = native_sponge.squeeze_field_elements(1)[0];

            let h_bits = native_h.into_bigint().to_bits_be();
            let skip = h_bits.len() - (self.crs.parameters.hash_to_prime_bits as usize - 1);
            let hash_bits: Vec<bool> = [
                vec![true].as_slice(),
                &h_bits[skip..],
            ].concat();

            let element = E::ScalarField::from_bigint(
                <E::ScalarField as PrimeField>::BigInt::from_bits_be(&hash_bits),
            ).unwrap();
            let integer = bigint_to_integer::<E::G1>(&element);

            let is_prime = integer.is_probably_prime(
                self.crs.parameters.security_level as u32 / 2,
            );
            if is_prime == IsPrime::No {
                continue;
            }
            return Ok((integer, index));
        }

        Err(HashToPrimeError::CouldNotFindIndex)
    }
}



#[cfg(test)]
pub mod test {
    use super::{HashToPrimeHashCircuit, HashToPrimeHashParameters, Protocol, Statement, Witness};
    use crate::{
        commitments::Commitment,
        parameters::Parameters,
        protocols::hash_to_prime::{
            snark_hash::Protocol as HPProtocol,
            transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
            HashToPrimeProtocol,
        },
        utils::integer_to_bigint_mod_q,
    };
    use accumulator::group::Rsa2048;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective};
    use merlin::Transcript;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use rand::thread_rng;
    use rug::rand::RandState;
    use rug::Integer;
    use std::cell::RefCell;
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_ff::PrimeField;

    pub struct TestParameters {}
    impl HashToPrimeHashParameters for TestParameters {
        const MESSAGE_SIZE: u16 = 254;
    }

    #[test]
    fn test_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let protocol = Protocol::<Bls12_381, TestParameters>::from_crs(&crs);

        let value = Integer::from(12);
        let (hashed_value, index) = protocol.hash_to_prime(&value, None).unwrap();
        let c = HashToPrimeHashCircuit::<Bls12_381, TestParameters> {
            security_level: crs.parameters.security_level,
            required_bit_size: crs.parameters.hash_to_prime_bits,
            value: Some(integer_to_bigint_mod_q::<G1Projective>(&value).unwrap()),
            index: Some(index),
            prime: Some(integer_to_bigint_mod_q::<G1Projective>(&hashed_value).unwrap()),
            parameters_type: std::marker::PhantomData,
        };
        c.generate_constraints(cs.clone()).unwrap();
        if !cs.is_satisfied().unwrap() {
            panic!(format!(
                "not satisfied: {:?}",
                cs.which_is_unsatisfied().unwrap()
            ));
        }
    }

    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let protocol = Protocol::<Bls12_381, TestParameters>::from_crs(&crs);

        let value = Integer::from(13);
        let (hashed_value, _) = protocol.hash_to_prime(&value, None).unwrap();
        let randomness = Integer::from(9);
        let commitment = protocol
            .crs
            .pedersen_commitment_parameters
            .commit(&hashed_value, &randomness)
            .unwrap();

        let proof_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
        let statement = Statement { c_e_q: commitment, nc: None, ciphertext: None };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        protocol
            .prove(
                &mut verifier_channel,
                &mut rng2,
                &statement,
                &Witness {
                    e: value,
                    r_q: randomness,
                    u_y: None,
                    e_sec: None,
                    email_bytes: None,
                },
            )
            .unwrap();

        let proof = verifier_channel.proof().unwrap();

        let verification_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
        let mut prover_channel =
            TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }

    #[test]
    fn test_poseidon_proof() {
        use super::{PoseidonProtocol, poseidon_config_for_test};
        use crate::protocols::hash_to_prime::HashToPrimeProtocol;
        use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
        use ark_crypto_primitives::sponge::CryptographicSponge;
        use ark_ff::UniformRand;

        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            PoseidonProtocol<Bls12_381>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let protocol = PoseidonProtocol::<Bls12_381>::from_crs(&crs);

        let value = Integer::from(13);
        let (hashed_value, _) = protocol.hash_to_prime(&value, None).unwrap();
        let randomness = Integer::from(9);
        let commitment = protocol.crs.pedersen_commitment_parameters
            .commit(&hashed_value, &randomness).unwrap();

        // Native computation of C — same as prove() does
        let salt = Fr::from(12345u64);
        let info = Fr::from(67890u64);
        let nc = Fr::from(1u64);
        let email_bytes = b"alice@example.com".to_vec();
        let e_sec = Fr::rand(&mut rng2);

        let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
        use ark_ec::Group;
        let shared_key = gen.mul_bigint(e_sec.into_bigint());
        let shared_affine = shared_key.into_affine();

        let poseidon_config = poseidon_config_for_test::<Fr>();
        let mut kdf_sponge = PoseidonSponge::new(&poseidon_config);
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

        let mut enc_sponge = PoseidonSponge::new(&poseidon_config);
        enc_sponge.absorb(&salt);
        enc_sponge.absorb(&k_pos);
        enc_sponge.absorb(&nc);
        let keystream: Fr = enc_sponge.squeeze_field_elements(1)[0];
        let ciphertext_native = m_native + keystream;

        // Prove with real e_sec and email_bytes
        let proof_transcript = RefCell::new(Transcript::new(b"poseidon_hash_to_prime"));
        let statement = Statement {
            c_e_q: commitment,
            nc: Some(nc),
            ciphertext: Some(ciphertext_native),
        };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        protocol.prove(
            &mut verifier_channel, &mut rng2, &statement,
            &Witness {
                e: value,
                r_q: randomness,
                u_y: None,
                e_sec: Some(e_sec),
                email_bytes: Some(email_bytes),
            },
        ).unwrap();

        let proof = verifier_channel.proof().unwrap();

        let verification_transcript = RefCell::new(Transcript::new(b"poseidon_hash_to_prime"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }

    #[test]
    #[ignore]
    fn bench_blake2s_vs_poseidon() {
        use super::{PoseidonProtocol, poseidon_config_for_test};
        use crate::protocols::hash_to_prime::HashToPrimeProtocol;
        use std::time::Instant;

        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        // ============================================================
        // Blake2s
        // ============================================================
        let blake_crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let blake_protocol = Protocol::<Bls12_381, TestParameters>::from_crs(&blake_crs);

        let value = Integer::from(13);
        let (blake_hashed, _) = blake_protocol.hash_to_prime(&value, None).unwrap();
        let randomness = Integer::from(9);
        let blake_commitment = blake_protocol.crs.pedersen_commitment_parameters
            .commit(&blake_hashed, &randomness).unwrap();

        let prove_start = Instant::now();
        let proof_transcript = RefCell::new(Transcript::new(b"blake2s"));
        let statement = Statement { c_e_q: blake_commitment, nc: None, ciphertext: None };
        let mut verifier_channel = TranscriptVerifierChannel::new(&blake_crs, &proof_transcript);
        blake_protocol.prove(
            &mut verifier_channel, &mut rng2, &statement,
            &Witness { e: value.clone(), r_q: randomness.clone(), u_y: None, e_sec:None, email_bytes: None },
        ).unwrap();
        let blake_prove_time = prove_start.elapsed();
        let blake_proof = verifier_channel.proof().unwrap();

        let verify_start = Instant::now();
        let verification_transcript = RefCell::new(Transcript::new(b"blake2s"));
        let mut prover_channel = TranscriptProverChannel::new(&blake_crs, &verification_transcript, &blake_proof);
        blake_protocol.verify(&mut prover_channel, &statement).unwrap();
        let blake_verify_time = verify_start.elapsed();

        // ============================================================
        // Poseidon
        // ============================================================
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));

        let poseidon_crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            PoseidonProtocol<Bls12_381>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let poseidon_protocol = PoseidonProtocol::<Bls12_381>::from_crs(&poseidon_crs);

        let value = Integer::from(13);
        let (poseidon_hashed, _) = poseidon_protocol.hash_to_prime(&value, None).unwrap();
        let randomness = Integer::from(9);
        let poseidon_commitment = poseidon_protocol.crs.pedersen_commitment_parameters
            .commit(&poseidon_hashed, &randomness).unwrap();

        let prove_start = Instant::now();
        let proof_transcript = RefCell::new(Transcript::new(b"poseidon"));
        let statement = Statement { c_e_q: poseidon_commitment, nc: Some(Fr::from(1u64)), ciphertext: Some(Fr::from(0u64)) };
        let mut verifier_channel = TranscriptVerifierChannel::new(&poseidon_crs, &proof_transcript);
        poseidon_protocol.prove(
            &mut verifier_channel, &mut rng2, &statement,
            &Witness { e: value.clone(), r_q: randomness.clone(), u_y: None, e_sec: None, email_bytes: None },
        ).unwrap();
        let poseidon_prove_time = prove_start.elapsed();
        let poseidon_proof = verifier_channel.proof().unwrap();

        let verify_start = Instant::now();
        let verification_transcript = RefCell::new(Transcript::new(b"poseidon"));
        let mut prover_channel = TranscriptProverChannel::new(&poseidon_crs, &verification_transcript, &poseidon_proof);
        poseidon_protocol.verify(&mut prover_channel, &statement).unwrap();
        let poseidon_verify_time = verify_start.elapsed();

        // ============================================================
        // Results
        // ============================================================
        println!("\n=== Hash-to-Prime Benchmark (λ=128, LegoGroth16) ===\n");
        println!("                 Blake2s         Poseidon        Improvement");
        println!("Prove time:      {:>12.1?}    {:>12.1?}    {:.1}x faster",
            blake_prove_time, poseidon_prove_time,
            blake_prove_time.as_secs_f64() / poseidon_prove_time.as_secs_f64());
        println!("Verify time:     {:>12.1?}    {:>12.1?}    {:.1}x faster",
            blake_verify_time, poseidon_verify_time,
            blake_verify_time.as_secs_f64() / poseidon_verify_time.as_secs_f64());
        println!();
        println!("CRS: LegoGroth16 ProvingKeyWithLink (contains VerifyingKeyWithLink)");
        println!("Proof: LegoGroth16 ProofWithLink (A, B, C in G1/G2 + link_d, link_pi in G1)");
        println!("  A: 48 bytes (G1), B: 96 bytes (G2), C: 48 bytes (G1)");
        println!("  d: 48 bytes (G1), link_d: 48 bytes (G1), link_pi: 48 bytes (G1)");
        println!("  Proof total: ~336 bytes");
    }
    #[test]
    fn bench_full_circuit() {
        use super::{PoseidonProtocol, poseidon_config_for_test};
        use crate::protocols::hash_to_prime::HashToPrimeProtocol;
        use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
        use ark_crypto_primitives::sponge::CryptographicSponge;
        use ark_ff::UniformRand;
        use ark_ec::{AffineRepr, CurveGroup, Group};
        use ark_ff::PrimeField;
        use std::time::Instant;

        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let setup_start = Instant::now();
        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            PoseidonProtocol<Bls12_381>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let setup_time = setup_start.elapsed();
        let protocol = PoseidonProtocol::<Bls12_381>::from_crs(&crs);

        let value = Integer::from(13);
        let (hashed_value, _) = protocol.hash_to_prime(&value, None).unwrap();
        let randomness = Integer::from(9);
        let commitment = protocol.crs.pedersen_commitment_parameters
            .commit(&hashed_value, &randomness).unwrap();
        use ark_serialize::CanonicalSerialize;
        let crs_size = crs.hash_to_prime_parameters.serialized_size(ark_serialize::Compress::Yes);
        let vk_size = crs.hash_to_prime_parameters.vk.serialized_size(ark_serialize::Compress::Yes);
        // Native computation of C
        let salt = Fr::from(12345u64);
        let info = Fr::from(67890u64);
        let nc = Fr::from(1u64);
        let email_bytes = b"alice@example.com".to_vec();
        let e_sec = Fr::rand(&mut rng2);

        let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
        let shared_key = gen.mul_bigint(e_sec.into_bigint());
        let shared_affine = shared_key.into_affine();

        let poseidon_config = poseidon_config_for_test::<Fr>();
        let mut kdf_sponge = PoseidonSponge::new(&poseidon_config);
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

        let mut enc_sponge = PoseidonSponge::new(&poseidon_config);
        enc_sponge.absorb(&salt);
        enc_sponge.absorb(&k_pos);
        enc_sponge.absorb(&nc);
        let keystream: Fr = enc_sponge.squeeze_field_elements(1)[0];
        let ciphertext_native = m_native + keystream;

        // Prove
        let prove_start = Instant::now();
        let proof_transcript = RefCell::new(Transcript::new(b"full_circuit"));
        let statement = Statement {
            c_e_q: commitment,
            nc: Some(nc),
            ciphertext: Some(ciphertext_native),
        };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        protocol.prove(
            &mut verifier_channel, &mut rng2, &statement,
            &Witness { e: value, r_q: randomness, u_y: None, e_sec: Some(e_sec), email_bytes: Some(email_bytes) },
        ).unwrap();
        let prove_time = prove_start.elapsed();
        let proof = verifier_channel.proof().unwrap();

        // Verify
        let verify_start = Instant::now();
        let verification_transcript = RefCell::new(Transcript::new(b"full_circuit"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
        let verify_time = verify_start.elapsed();

        println!("\n=== Full Circuit Benchmark (λ=128) ===");
        println!("Current: Poseidon hash-to-prime + EC Diffie-Hellman + KDF + KeyStream + Symmetric Encryption");
        println!("CRS size (pk):  {} bytes ({:.1} KB)", crs_size, crs_size as f64 / 1024.0);
        println!("VK size:        {} bytes ({:.1} KB)", vk_size, vk_size as f64 / 1024.0);
        println!("Setup time:     {:?}", setup_time);
        println!("Prove time:     {:?}", prove_time);
        println!("Verify time:    {:?}", verify_time);
    }
}
