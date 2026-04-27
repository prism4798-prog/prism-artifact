//! Auth Verifier: Verify a ZK authentication proof π_auth.
//!
//! Usage:
//!   ./auth_verifier --crs-dir ./zkp-data \
//!     --proof auth_proof.bin \
//!     --t-exp <value> --ciphertext-c <b64>

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

use cpsnarks_set::serialization;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut crs_dir = PathBuf::from("./zkp-data");
    let mut proof_file = None;
    let mut t_exp_str: Option<String> = None;
    let mut ciphertext_c_str = None;
    let mut max_session_lifetime: u64 = 3600;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--crs-dir" => { i += 1; crs_dir = PathBuf::from(&args[i]); }
            "--proof" => { i += 1; proof_file = Some(PathBuf::from(&args[i])); }
            "--t-exp" => { i += 1; t_exp_str = Some(args[i].clone()); }
            "--ciphertext-c" => { i += 1; ciphertext_c_str = Some(args[i].clone()); }
            "--max-lifetime" => { i += 1; max_session_lifetime = args[i].parse().unwrap(); }
            "--help" | "-h" => {
                eprintln!("Usage: auth_verifier [OPTIONS]");
                eprintln!("  --crs-dir DIR         ZKP data directory");
                eprintln!("  --proof FILE          Auth proof file (.bin)");
                eprintln!("  --t-exp VALUE          Session expiry timestamp");
                eprintln!("  --ciphertext-c VALUE  Sender ciphertext C (base64)");
                eprintln!("  --max-lifetime SECS   Max session lifetime (default 3600)");
                eprintln!("\nExit: 0=ACCEPT, 1=REJECT, 2=ERROR");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(2); }
        }
        i += 1;
    }

    // Load verification key
    eprintln!("[auth_verifier] Loading auth verification key...");
    let t0 = Instant::now();

    let vk_groth: VerifyingKey<Bls12_381> = {
        let vk_path = crs_dir.join("auth_vk.bin");
        let bytes = fs::read(&vk_path)
            .unwrap_or_else(|e| {
                eprintln!("[auth_verifier] ERROR: Cannot read {}: {}", vk_path.display(), e);
                std::process::exit(2);
            });
        VerifyingKey::deserialize_compressed(&bytes[..])
            .unwrap_or_else(|e| {
                eprintln!("[auth_verifier] ERROR: Cannot deserialize VK: {}", e);
                std::process::exit(2);
            })
    };

    let (pk_op_x, pk_op_y) = {
        let pk_path = crs_dir.join("auth_pk_op.bin");
        let mut f = BufReader::new(
            fs::File::open(&pk_path).unwrap_or_else(|e| {
                eprintln!("[auth_verifier] ERROR: Cannot open {}: {}", pk_path.display(), e);
                std::process::exit(2);
            })
        );
        let x = serialization::read_fr(&mut f).unwrap();
        let y = serialization::read_fr(&mut f).unwrap();
        (x, y)
    };

    let iss = {
        let iss_path = crs_dir.join("auth_iss.bin");
        let mut f = BufReader::new(
            fs::File::open(&iss_path).unwrap_or_else(|e| {
                eprintln!("[auth_verifier] ERROR: Cannot open {}: {}", iss_path.display(), e);
                std::process::exit(2);
            })
        );
        serialization::read_fr(&mut f).unwrap()
    };

    eprintln!("[auth_verifier] VK loaded in {:.1?}", t0.elapsed());

    // Parse proof
    let proof_bytes = {
        let path = proof_file.unwrap_or_else(|| {
            eprintln!("[auth_verifier] ERROR: --proof is required");
            std::process::exit(2);
        });
        fs::read(&path).unwrap_or_else(|e| {
            eprintln!("[auth_verifier] ERROR: Cannot read {}: {}", path.display(), e);
            std::process::exit(2);
        })
    };

    let proof: Proof<Bls12_381> = Proof::deserialize_compressed(&proof_bytes[..])
        .unwrap_or_else(|e| {
            eprintln!("[auth_verifier] ERROR: Cannot deserialize proof: {}", e);
            std::process::exit(2);
        });

    let t_exp_val: String = t_exp_str.clone()
        .unwrap_or_else(|| { eprintln!("--t-exp required"); std::process::exit(2); });
    let t_exp: Fr = Fr::from(t_exp_val.parse::<u64>().unwrap());

    let ciphertext_c: Fr = {
        let s = ciphertext_c_str.unwrap_or_else(|| {
            eprintln!("--ciphertext-c required"); std::process::exit(2);
        });
        let bytes = base64_decode(&s);
        Fr::deserialize_compressed(&bytes[..]).unwrap_or_else(|e| {
            eprintln!("[auth_verifier] ERROR: Cannot deserialize C: {}", e);
            std::process::exit(2);
        })
    };

    // Check session expiry
    let t_cur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs();
    let t_exp_u64: u64 = t_exp_val.parse().unwrap();

    if t_cur > t_exp_u64 {
        eprintln!("[auth_verifier] REJECT — session expired (cur={}, exp={})", t_cur, t_exp_u64);
        println!("{{");
        println!("  \"result\": \"REJECT\",");
        println!("  \"reason\": \"session_expired\"");
        println!("}}");
        std::process::exit(1);
    }

    if t_exp_u64 > t_cur + max_session_lifetime {
        eprintln!("[auth_verifier] REJECT — expiry too far in future");
        println!("{{");
        println!("  \"result\": \"REJECT\",");
        println!("  \"reason\": \"expiry_too_far\"");
        println!("}}");
        std::process::exit(1);
    }

    // Verify proof
    eprintln!("[auth_verifier] Verifying auth proof...");
    let t1 = Instant::now();

    // Public inputs: pk_op_x, pk_op_y, iss, t_exp, ciphertext_c
    let public_inputs = vec![
        pk_op_x,
        pk_op_y,
        iss,
        t_exp,
        ciphertext_c,
    ];

    match Groth16::<Bls12_381>::verify(&vk_groth, &public_inputs, &proof) {
        Ok(true) => {
            let verify_time = t1.elapsed();
            eprintln!("[auth_verifier] ACCEPT — auth proof valid ({:.1?})", verify_time);
            println!("{{");
            println!("  \"result\": \"ACCEPT\",");
            println!("  \"verify_time_ms\": {}", verify_time.as_millis());
            println!("}}");
            std::process::exit(0);
        }
        Ok(false) => {
            let verify_time = t1.elapsed();
            eprintln!("[auth_verifier] REJECT — auth proof invalid ({:.1?})", verify_time);
            println!("{{");
            println!("  \"result\": \"REJECT\",");
            println!("  \"reason\": \"invalid_proof\",");
            println!("  \"verify_time_ms\": {}", verify_time.as_millis());
            println!("}}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[auth_verifier] ERROR — verification error: {:?}", e);
            println!("{{");
            println!("  \"result\": \"ERROR\",");
            println!("  \"error\": \"{:?}\"", e);
            println!("}}");
            std::process::exit(2);
        }
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    let table: Vec<u8> = (0..256u16).map(|c| match c as u8 {
        b'A'..=b'Z' => c as u8 - b'A',
        b'a'..=b'z' => c as u8 - b'a' + 26,
        b'0'..=b'9' => c as u8 - b'0' + 52,
        b'+' => 62, b'/' => 63, _ => 0,
    }).collect();
    let input: Vec<u8> = s.bytes().filter(|&b| b != b'=' && b != b'\n').collect();
    let mut out = Vec::new();
    for chunk in input.chunks(4) {
        if chunk.len() < 2 { break; }
        let a = table[chunk[0] as usize] as u32;
        let b = table[chunk[1] as usize] as u32;
        let c = if chunk.len() > 2 { table[chunk[2] as usize] as u32 } else { 0 };
        let d = if chunk.len() > 3 { table[chunk[3] as usize] as u32 } else { 0 };
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk.len() > 2 { out.push(((triple >> 8) & 0xFF) as u8); }
        if chunk.len() > 3 { out.push((triple & 0xFF) as u8); }
    }
    out
}
