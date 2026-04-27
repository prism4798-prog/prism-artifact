//! Auth Prover: Generate a ZK authentication proof π_auth.
//!
//! Called AFTER the existing ./prover (which produces C).
//!
//! Usage:
//!   ./auth_prover --crs-dir ./zkp-data \
//!     --token token.bin \
//!     --t-exp <timestamp> \
//!     --ciphertext-c <b64> \
//!     --keystream-s <b64>

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::thread_rng;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

use cpsnarks_set::protocols::zkauth::{
    read_zk_token, AuthCircuit, AuthPrivateWitnesses, AuthPublicInputs, ZkToken,
};
use cpsnarks_set::serialization;

fn to_b64(data: &[u8]) -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn fr_to_b64(f: &Fr) -> String {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).unwrap();
    to_b64(&buf)
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut crs_dir = PathBuf::from("./zkp-data");
    let mut token_file = None;
    let mut t_exp_str = None;
    let mut ciphertext_c_str = None;
    let mut keystream_s_str = None;
    let mut output_file = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--crs-dir" => { i += 1; crs_dir = PathBuf::from(&args[i]); }
            "--token" => { i += 1; token_file = Some(PathBuf::from(&args[i])); }
            "--t-exp" => { i += 1; t_exp_str = Some(args[i].clone()); }
            "--ciphertext-c" => { i += 1; ciphertext_c_str = Some(args[i].clone()); }
            "--keystream-s" => { i += 1; keystream_s_str = Some(args[i].clone()); }
            "--output" | "-o" => { i += 1; output_file = Some(PathBuf::from(&args[i])); }
            "--help" | "-h" => {
                eprintln!("Usage: auth_prover [OPTIONS]");
                eprintln!("  --crs-dir DIR        ZKP data directory");
                eprintln!("  --token FILE         ZK token file (.bin)");
                eprintln!("  --t-exp VALUE        Session expiry timestamp");
                eprintln!("  --ciphertext-c VALUE Sender ciphertext C (base64)");
                eprintln!("  --keystream-s VALUE  Keystream S from CP_IdEnc (base64)");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    // Load inputs
    eprintln!("[auth_prover] Loading auth CRS...");
    let t0 = Instant::now();

    let pk_groth: ProvingKey<Bls12_381> = {
        let crs_path = crs_dir.join("auth_crs.bin");
        let bytes = fs::read(&crs_path)
            .unwrap_or_else(|e| panic!("Cannot read {}: {}", crs_path.display(), e));
        ProvingKey::deserialize_compressed(&bytes[..])
            .expect("Failed to deserialize auth proving key")
    };
    eprintln!("[auth_prover] CRS loaded in {:.1?}", t0.elapsed());

    let (pk_op_x, pk_op_y) = {
        let pk_path = crs_dir.join("auth_pk_op.bin");
        let mut f = BufReader::new(fs::File::open(&pk_path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", pk_path.display(), e)));
        let x = serialization::read_fr(&mut f).unwrap();
        let y = serialization::read_fr(&mut f).unwrap();
        (x, y)
    };

    let iss = {
        let iss_path = crs_dir.join("auth_iss.bin");
        let mut f = BufReader::new(fs::File::open(&iss_path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", iss_path.display(), e)));
        serialization::read_fr(&mut f).unwrap()
    };

    let token: ZkToken = {
        let tok_path = token_file.expect("--token is required");
        let mut f = BufReader::new(fs::File::open(&tok_path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", tok_path.display(), e)));
        read_zk_token(&mut f).expect("Failed to read ZK token")
    };

    let t_exp: Fr = Fr::from(
        t_exp_str.expect("--t-exp required").parse::<u64>().unwrap()
    );
    let ciphertext_c: Fr = {
        let bytes = base64_decode(&ciphertext_c_str.expect("--ciphertext-c required"));
        Fr::deserialize_compressed(&bytes[..]).expect("deserialize C")
    };
    let keystream_s: Fr = {
        let bytes = base64_decode(&keystream_s_str.expect("--keystream-s required"));
        Fr::deserialize_compressed(&bytes[..]).expect("deserialize S")
    };

    eprintln!("[auth_prover] All inputs loaded");

    // Build and prove
    eprintln!("[auth_prover] Generating auth proof...");
    let t1 = Instant::now();

    let circuit = AuthCircuit {
        public_inputs: AuthPublicInputs {
            pk_op_x,
            pk_op_y,
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

    let mut rng = thread_rng();
    let proof = Groth16::<Bls12_381>::prove(&pk_groth, circuit, &mut rng)
        .expect("Proof generation failed");

    let prove_time = t1.elapsed();
    eprintln!("[auth_prover] Auth proof generated in {:.3?}", prove_time);

    // Serialize
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    if let Some(ref out_path) = output_file {
        fs::write(out_path, &proof_bytes).unwrap();
        eprintln!("[auth_prover] Proof written to {} ({} bytes)",
            out_path.display(), proof_bytes.len());
    }

    // JSON to stdout
    println!("{{");
    println!("  \"auth_proof_b64\": \"{}\",", to_b64(&proof_bytes));
    println!("  \"pk_op_x\": \"{}\",", fr_to_b64(&pk_op_x));
    println!("  \"pk_op_y\": \"{}\",", fr_to_b64(&pk_op_y));
    println!("  \"iss\": \"{}\",", fr_to_b64(&iss));
    println!("  \"t_exp\": \"{}\",", fr_to_b64(&t_exp));
    println!("  \"ciphertext_c\": \"{}\",", fr_to_b64(&ciphertext_c));
    println!("  \"prove_time_ms\": {},", prove_time.as_millis());
    println!("  \"proof_size_bytes\": {}", proof_bytes.len());
    println!("}}");
}
