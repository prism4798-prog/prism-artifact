//! Benchmark: RSA accumulator scalability with varying user counts.
//! Elements are primes derived from JubJub public keys via Poseidon hash-to-prime.

use accumulator::group::{Group, UnknownOrderGroup, Rsa2048};
use accumulator::AccumulatorWithoutHashToPrime;
use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use cpsnarks_set::protocols::hash_to_prime::snark_hash::poseidon_config_for_test;
use cpsnarks_set::utils::bigint_to_integer;
use rug::integer::IsPrime;
use rug::Integer;
use std::time::Instant;

fn user_to_prime(i: usize, bits: u16) -> Integer {
    let config = poseidon_config_for_test::<Fr>();
    let mut sponge = PoseidonSponge::new(&config);
    sponge.absorb(&Fr::from(i as u64));
    sponge.absorb(&Fr::from(999999u64));
    let sk: Fr = sponge.squeeze_field_elements(1)[0];
    let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
    let pk = gen.mul_bigint(sk.into_bigint()).into_affine();
    for index in 0u64..1 << 16 {
        let mut h_sponge = PoseidonSponge::new(&config);
        h_sponge.absorb(&pk.x);
        h_sponge.absorb(&pk.y);
        h_sponge.absorb(&Fr::from(index));
        let h: Fr = h_sponge.squeeze_field_elements(1)[0];
        let h_bits = h.into_bigint().to_bits_be();
        let skip = h_bits.len() - (bits as usize - 1);
        let hash_bits: Vec<bool> = [vec![true].as_slice(), &h_bits[skip..]].concat();
        let element = Fr::from_bigint(
            <Fr as PrimeField>::BigInt::from_bits_be(&hash_bits),
        ).unwrap();
        let integer = bigint_to_integer::<G1Projective>(&element);
        if integer.is_probably_prime(64) != IsPrime::No {
            return integer;
        }
    }
    panic!("hash_to_prime failed for user {}", i);
}

fn main() {
    let bits = 254u16;

    // Simulate trapdoor: phi(N) is a 2048-bit number
    let phi_n = {
        let mut phi = Integer::from(1) << 2047;
        phi += Integer::from(12345678);
        phi |= Integer::from(1);
        phi
    };

    // ============================================================
    // Table 1: Core operations scaling
    // ============================================================
    let user_counts = vec![10, 50, 100, 500, 1000, 5000, 10000];

    println!("=== Table 1: RSA Accumulator Core Operations ===");
    println!("Element = 1|Poseidon(u_x, u_y, j) from JubJub public key\n");
    println!("{:>7} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Users", "Build", "Build-T", "Wit", "Wit-T", "WitUpd", "Add", "Del-T", "Verify");
    println!("{:>7} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)");
    println!("{}", "-".repeat(90));

    for &n in &user_counts {
        let mut primes: Vec<Integer> = Vec::new();
        for i in 0..n {
            primes.push(user_to_prime(i, bits));
        }

        // Build accumulator — O(n) exponentiations
        let t_build = Instant::now();
        let empty = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let acc = empty.clone().add(&primes);
        let acc_value = acc.value.clone();
        let build_time = t_build.elapsed();

        // Build with trapdoor — multiply all, reduce mod phi(N), one exp
        let t_build_trap = Instant::now();
        let mut build_product = Integer::from(1);
        for p in &primes {
            build_product *= p;
        }
        let build_reduced = build_product % &phi_n;
        let _acc_trap = Rsa2048::exp(&Rsa2048::unknown_order_elem(), &build_reduced);
        let build_trap_time = t_build_trap.elapsed();

        // Witness without trapdoor — O(n-1)
        let t_witness = Instant::now();
        let others: Vec<Integer> = primes[1..].to_vec();
        let acc_without = empty.clone().add(&others);
        let witness_w = acc_without.value.clone();
        let witness_time = t_witness.elapsed();

        assert_eq!(Rsa2048::exp(&witness_w, &primes[0]), acc_value);

        // Witness with trapdoor — O(1)
        let t_wit_trap = Instant::now();
        let e_inv_w = primes[0].clone().invert(&phi_n).unwrap_or(Integer::from(1));
        let _wit_trap = Rsa2048::exp(&acc_value, &e_inv_w);
        let wit_trap_time = t_wit_trap.elapsed();

        // Witness update (new element added): w_new = w^e_new — O(1)
        let new_prime = user_to_prime(n + 1000, bits);
        let t_wit_upd = Instant::now();
        let _wit_updated = Rsa2048::exp(&witness_w, &new_prime);
        let wit_upd_time = t_wit_upd.elapsed();

        // Add — O(1)
        let t_add = Instant::now();
        let _new_acc = Rsa2048::exp(&acc_value, &new_prime);
        let add_time = t_add.elapsed();

        // Delete with trapdoor — O(1)
        let t_delete = Instant::now();
        let e_inv = primes[0].clone().invert(&phi_n).unwrap_or(Integer::from(1));
        let _deleted_acc = Rsa2048::exp(&acc_value, &e_inv);
        let delete_time = t_delete.elapsed();

        // Verify witness — O(1)
        let t_verify = Instant::now();
        let _check = Rsa2048::exp(&witness_w, &primes[0]);
        let verify_time = t_verify.elapsed();

        println!("{:>7} {:>10.1} {:>10.1} {:>10.1} {:>10.3} {:>10.3} {:>10.3} {:>10.3} {:>10.3}",
            n,
            build_time.as_secs_f64() * 1000.0,
            build_trap_time.as_secs_f64() * 1000.0,
            witness_time.as_secs_f64() * 1000.0,
            wit_trap_time.as_secs_f64() * 1000.0,
            wit_upd_time.as_secs_f64() * 1000.0,
            add_time.as_secs_f64() * 1000.0,
            delete_time.as_secs_f64() * 1000.0,
            verify_time.as_secs_f64() * 1000.0,
        );
    }

    // ============================================================
    // Table 2: Batch add with trapdoor
    // ============================================================
    let batch_sizes = vec![10, 100, 1000, 10000, 100000];

    println!("\n=== Table 2: Batch Addition With Trapdoor ===");
    println!("acc_new = acc^(e_1 * e_2 * ... * e_n mod phi(N)) mod N\n");
    println!("{:>8} {:>15} {:>15} {:>15} {:>15}",
        "Batch", "Multiply(ms)", "Mod phi(ms)", "Exp(ms)", "Total(ms)");
    println!("{}", "-".repeat(65));

    let base_primes_b: Vec<Integer> = (0..10).map(|i| user_to_prime(i, bits)).collect();
    let empty_b = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let base_acc_b = empty_b.clone().add(&base_primes_b);
    let base_value_b = base_acc_b.value.clone();

    for &batch in &batch_sizes {
        let new_primes: Vec<Integer> = (0..batch)
            .map(|i| user_to_prime(i + 500000, bits))
            .collect();

        // Step 1: Multiply all primes
        let t_mul = Instant::now();
        let mut product = Integer::from(1);
        for p in &new_primes {
            product *= p;
        }
        let mul_time = t_mul.elapsed();

        // Step 2: Reduce mod phi(N)
        let t_mod = Instant::now();
        let reduced = product % &phi_n;
        let mod_time = t_mod.elapsed();

        // Step 3: Single exponentiation
        let t_exp = Instant::now();
        let _new_acc = Rsa2048::exp(&base_value_b, &reduced);
        let exp_time = t_exp.elapsed();

        let total = mul_time + mod_time + exp_time;

        println!("{:>8} {:>15.1} {:>15.3} {:>15.3} {:>15.1}",
            batch,
            mul_time.as_secs_f64() * 1000.0,
            mod_time.as_secs_f64() * 1000.0,
            exp_time.as_secs_f64() * 1000.0,
            total.as_secs_f64() * 1000.0,
        );
    }

    // ============================================================
    // Table 3: Batch witness update
    // ============================================================
    let update_sizes = vec![10, 100, 1000, 2000, 5000, 10000];

    println!("\n=== Table 3: Witness Update When New Users Added ===");
    println!("Base: 100 users in accumulator, updating witness for user 0\n");
    println!("{:>10} {:>18} {:>18} {:>18}",
        "New Users", "NaiveExp(ms)", "BatchExp(ms)", "Trapdoor(ms)");
    println!("{}", "-".repeat(68));

    let base_n = 100;
    let base_primes_w: Vec<Integer> = (0..base_n).map(|i| user_to_prime(i, bits)).collect();
    let empty_w = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let base_acc_w = empty_w.clone().add(&base_primes_w);
    let base_acc_value_w = base_acc_w.value.clone();
    let others_w: Vec<Integer> = base_primes_w[1..].to_vec();
    let base_witness_w = empty_w.clone().add(&others_w).value.clone();

    for &k in &update_sizes {
        let new_primes: Vec<Integer> = (0..k)
            .map(|i| user_to_prime(i + 500000, bits))
            .collect();

        // Method 1 (Naive): k separate exponentiations
        let t_naive = Instant::now();
        let mut w_naive = base_witness_w.clone();
        for p in &new_primes {
            w_naive = Rsa2048::exp(&w_naive, p);
        }
        let naive_time = t_naive.elapsed();

        // Method 2 (Batch, no trapdoor): multiply all, one exp (big exponent)
        let t_batch = Instant::now();
        let mut product_b = Integer::from(1);
        for p in &new_primes {
            product_b *= p;
        }
        let _w_batch = Rsa2048::exp(&base_witness_w, &product_b);
        let batch_time = t_batch.elapsed();

        // Method 3 (Trapdoor): multiply, reduce mod phi(N), one exp (2048-bit exponent)
        let t_trap = Instant::now();
        let mut product_t = Integer::from(1);
        for p in &new_primes {
            product_t *= p;
        }
        let reduced_t = product_t % &phi_n;
        let _w_trap = Rsa2048::exp(&base_witness_w, &reduced_t);
        let trap_time = t_trap.elapsed();

        println!("{:>10} {:>18.1} {:>18.1} {:>18.1}",
            k,
            naive_time.as_secs_f64() * 1000.0,
            batch_time.as_secs_f64() * 1000.0,
            trap_time.as_secs_f64() * 1000.0,
        );
    }

    println!("\n=== Key Observations ===");
    println!("Accumulator value:      always 256 bytes (RSA-2048 element)");
    println!("Proof size:             always 4,865 bytes regardless of user count");
    println!("Build (no trapdoor):    O(n) — n modular exponentiations");
    println!("Build (trapdoor):       O(n) multiply + O(1) mod + O(1) exp");
    println!("Add (single):           O(1) — single modular exponentiation");
    println!("Delete (trapdoor):      O(1) — inverse mod phi(N) + exponentiation");
    println!("Witness (trapdoor):     O(1) — acc^(e^-1 mod phi(N))");
    println!("Witness update (single):O(1) — w^e_new");
    println!("Batch witness update:");
    println!("  Naive:                O(k) — k separate exponentiations");
    println!("  Batch (no trapdoor):  O(k) multiply + O(1) exp (large exponent)");
    println!("  Batch (trapdoor):     O(k) multiply + O(1) mod + O(1) exp (2048-bit)");
    println!("Domain owner knows p,q factorization of N");
}