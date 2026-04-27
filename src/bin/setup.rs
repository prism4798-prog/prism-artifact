//! Setup: Generate CRS + accumulator from a list of user identifiers.
//!
//! Usage:
//!   cargo run --bin setup --features arkworks -- \
//!     --out-dir ./zkp-data \
//!     --users users.csv
//!
//! Outputs:
//!   zkp-data/crs.bin
//!   zkp-data/accumulator.bin
//!   zkp-data/witnesses/<email>.bin  (per-user: sk, pk, prime, accumulator witness)

use accumulator::group::{ElemFrom, ElemToBytes, Group, Rsa2048};
use accumulator::AccumulatorWithoutHashToPrime;
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup, Group as ArkGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use cpsnarks_set::parameters::Parameters;
use cpsnarks_set::protocols::hash_to_prime::snark_hash::{
    poseidon_config_for_test, PoseidonProtocol,
};
use cpsnarks_set::protocols::membership;
use cpsnarks_set::serialization;
use cpsnarks_set::utils::bigint_to_integer;
use rand::thread_rng;
use rug::integer::IsPrime;
use rug::rand::RandState;
use rug::Integer;
use std::fs;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Instant;

/// Derive a JubJub keypair from an email address (deterministic for reproducibility).
/// Returns (secret_key, pub_x, pub_y).
fn email_to_jubjub_keypair(email: &str) -> (Fr, Fr, Fr) {
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    let config = poseidon_config_for_test::<Fr>();

    // Hash email bytes to get a deterministic secret key
    let mut sponge = PoseidonSponge::new(&config);
    // Absorb each byte as a field element
    for &b in email.as_bytes() {
        sponge.absorb(&Fr::from(b as u64));
    }
    // Add domain separator
    sponge.absorb(&Fr::from(999999u64));
    let sk: Fr = sponge.squeeze_field_elements(1)[0];

    // Compute public key: pk = sk * generator
    let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
    let pk = gen.mul_bigint(sk.into_bigint()).into_affine();

    (sk, pk.x, pk.y)
}

/// Compute hash-to-prime using Poseidon on (u_x, u_y, j) — same logic as
/// PoseidonProtocol::hash_to_prime but with CUSTOM (u_x, u_y) instead of generator.
fn hash_to_prime_with_key(
    u_x: &Fr,
    u_y: &Fr,
    hash_to_prime_bits: u16,
) -> (Integer, u64) {
    let config = poseidon_config_for_test::<Fr>();

    for index in 0u64..1 << 16 {
        let mut sponge = PoseidonSponge::new(&config);
        sponge.absorb(u_x);
        sponge.absorb(u_y);
        sponge.absorb(&Fr::from(index));
        let h: Fr = sponge.squeeze_field_elements(1)[0];

        let h_bits = h.into_bigint().to_bits_be();
        let skip = h_bits.len() - (hash_to_prime_bits as usize - 1);
        let hash_bits: Vec<bool> = [
            vec![true].as_slice(),
            &h_bits[skip..],
        ].concat();

        let element = Fr::from_bigint(
            <Fr as PrimeField>::BigInt::from_bits_be(&hash_bits),
        ).unwrap();
        let integer = bigint_to_integer::<G1Projective>(&element);

        let is_prime = integer.is_probably_prime(64);
        if is_prime == IsPrime::No {
            continue;
        }
        return (integer, index);
    }

    panic!("Could not find prime in 2^16 attempts");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut out_dir = PathBuf::from("./zkp-data");
    let mut users_file = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out-dir" => { i += 1; out_dir = PathBuf::from(&args[i]); }
            "--users" => { i += 1; users_file = Some(PathBuf::from(&args[i])); }
            "--help" | "-h" => {
                println!("Usage: setup [--out-dir DIR] [--users FILE]");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    let users: Vec<String> = match users_file {
        Some(path) => {
            let content = fs::read_to_string(&path).unwrap();
            content.lines().map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        }
        None => {
            println!("[setup] No --users file; using demo set.");
            vec![
                "alice@senderdomain.org".to_string(),
                "bob@receiverdomain.org".to_string(),
                "carol@receiverdomain.org".to_string(),
            ]
        }
    };

    println!("[setup] {} users to accumulate", users.len());

    fs::create_dir_all(&out_dir).expect("create out dir");
    let witnesses_dir = out_dir.join("witnesses");
    fs::create_dir_all(&witnesses_dir).expect("create witnesses dir");

    // ============================================================
    // Step 1: Generate CRS
    // ============================================================
    println!("[setup] Generating CRS (trusted setup)...");
    let t0 = Instant::now();

    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let protocol = membership::Protocol::<
        Rsa2048, G1Projective, PoseidonProtocol<Bls12_381>,
    >::setup(&params, &mut rng1, &mut rng2).expect("CRS generation failed");
    let crs = protocol.crs;
    println!("[setup] CRS generated in {:.1?}", t0.elapsed());

    // ============================================================
    // Step 2: Generate JubJub keypair per user, hash to unique prime
    // ============================================================
    println!("[setup] Generating per-user keypairs and primes...");
    let t1 = Instant::now();

    struct UserData {
        email: String,
        sk: Fr,
        u_x: Fr,
        u_y: Fr,
        prime: Integer,
    }

    let mut user_data: Vec<UserData> = Vec::new();
    for email in &users {
        let (sk, u_x, u_y) = email_to_jubjub_keypair(email);
        let (prime, index) = hash_to_prime_with_key(&u_x, &u_y, params.hash_to_prime_bits);
        println!("  {} → prime index={}, prime(8)={}...",
            email, index, &prime.to_string()[..std::cmp::min(8, prime.to_string().len())]);
        user_data.push(UserData { email: email.clone(), sk, u_x, u_y, prime });
    }

    // Verify all primes are unique
    for i in 0..user_data.len() {
        for j in (i+1)..user_data.len() {
            assert_ne!(user_data[i].prime, user_data[j].prime,
                "FATAL: {} and {} produced the same prime!",
                user_data[i].email, user_data[j].email);
        }
    }
    println!("[setup] All primes unique. Done in {:.1?}", t1.elapsed());

    // ============================================================
    // Step 3: Build RSA accumulator
    // ============================================================
    println!("[setup] Building RSA accumulator...");
    let t2 = Instant::now();

    let all_primes: Vec<Integer> = user_data.iter().map(|u| u.prime.clone()).collect();

    let empty_acc = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let acc_with_all = empty_acc.clone().add(&all_primes);
    let acc_value = acc_with_all.value.clone();

    println!("[setup] Accumulator built in {:.1?} ({} bytes)",
        t2.elapsed(), Rsa2048::elem_to_bytes(&acc_value).len());

    // ============================================================
    // Step 4: Compute per-user witnesses
    // ============================================================
    println!("[setup] Computing per-user membership witnesses...");
    let t3 = Instant::now();

    for ud in &user_data {
        let others: Vec<Integer> = all_primes.iter()
            .filter(|p| *p != &ud.prime).cloned().collect();
        let acc_without = empty_acc.clone().add(&others);
        let w = acc_without.value.clone();

        assert_eq!(Rsa2048::exp(&w, &ud.prime), acc_value,
            "witness verification failed for {}", ud.email);

        // Write witness file: sk, u_x, u_y, prime, witness_w
        let witness_path = witnesses_dir.join(format!("{}.bin", ud.email));
        let mut f = BufWriter::new(fs::File::create(&witness_path).unwrap());
        serialization::write_fr(&mut f, &ud.sk).unwrap();
        serialization::write_fr(&mut f, &ud.u_x).unwrap();
        serialization::write_fr(&mut f, &ud.u_y).unwrap();
        serialization::write_integer(&mut f, &ud.prime).unwrap();
        serialization::write_rsa_elem(&mut f, &w).unwrap();
        println!("  {} → {}", ud.email, witness_path.display());
    }
    println!("[setup] Witnesses computed in {:.1?}", t3.elapsed());

    // ============================================================
    // Step 5: Serialize CRS + accumulator
    // ============================================================
    println!("[setup] Serializing...");

    let crs_path = out_dir.join("crs.bin");
    {
        let mut f = BufWriter::new(fs::File::create(&crs_path).unwrap());
        serialization::write_crs(&mut f, &crs).unwrap();
    }
    let crs_size = fs::metadata(&crs_path).unwrap().len();
    println!("  crs.bin: {} bytes ({:.1} KB)", crs_size, crs_size as f64 / 1024.0);

    let vk_path = out_dir.join("vk.bin");
    {
        let mut f = BufWriter::new(fs::File::create(&vk_path).unwrap());
        serialization::write_verifier_crs(&mut f, &crs).unwrap();
    }
    let vk_size = fs::metadata(&vk_path).unwrap().len();
    println!("  vk.bin: {} bytes ({:.1} KB)", vk_size, vk_size as f64 / 1024.0);

    let acc_path = out_dir.join("accumulator.bin");
    {
        let mut f = BufWriter::new(fs::File::create(&acc_path).unwrap());
        serialization::write_accumulator(&mut f, &acc_value).unwrap();
    }
    let acc_size = fs::metadata(&acc_path).unwrap().len();
    println!("  accumulator.bin: {} bytes", acc_size);

    println!("\n=== Setup Complete ===");
    println!("Users accumulated: {}", users.len());
}
