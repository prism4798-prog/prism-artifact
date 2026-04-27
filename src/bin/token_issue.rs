//! Token Issue: Issue a ZK-friendly identity token for a user.
//!
//! Usage:
//!   ./token_issue --crs-dir ./zkp-data \
//!     --email alice@senderdomain.org \
//!     --t-exp <value> \
//!     -o token.bin

use ark_bls12_381::Fr;
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381::EdwardsAffine as JubJubAffine;
use ark_ff::PrimeField;
use rand::thread_rng;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

use cpsnarks_set::protocols::zkauth::{
    compute_iss, pack_email_to_field,
    token_issue, token_verify, write_zk_token,
};
use cpsnarks_set::serialization;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut crs_dir = PathBuf::from("./zkp-data");
    let mut email = None;
    let mut t_exp_str = None;
    let mut output_file = PathBuf::from("token.bin");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--crs-dir" => { i += 1; crs_dir = PathBuf::from(&args[i]); }
            "--email" => { i += 1; email = Some(args[i].clone()); }
            "--t-exp" => { i += 1; t_exp_str = Some(args[i].clone()); }
            "--output" | "-o" => { i += 1; output_file = PathBuf::from(&args[i]); }
            "--help" | "-h" => {
                eprintln!("Usage: token_issue [OPTIONS]");
                eprintln!("  --crs-dir DIR     ZKP data directory (default: ./zkp-data)");
                eprintln!("  --email EMAIL     User email address (required)");
                eprintln!("  --t-exp VALUE     Session expiry timestamp (optional, now+3600 if omitted)");
                eprintln!("  -o FILE           Output token file (default: token.bin)");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    let email = email.unwrap_or_else(|| {
        eprintln!("ERROR: --email is required");
        std::process::exit(1);
    });

    let mut rng = thread_rng();

    // Load sk_OP and pk_OP
    eprintln!("[token_issue] Loading Keycloak keys...");

    let sk_op: Fr = {
        let path = crs_dir.join("auth_sk_op.bin");
        let mut f = BufReader::new(fs::File::open(&path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", path.display(), e)));
        serialization::read_fr(&mut f).unwrap()
    };

    let (pk_op_x, pk_op_y) = {
        let path = crs_dir.join("auth_pk_op.bin");
        let mut f = BufReader::new(fs::File::open(&path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", path.display(), e)));
        let x = serialization::read_fr(&mut f).unwrap();
        let y = serialization::read_fr(&mut f).unwrap();
        (x, y)
    };
    let pk_op = JubJubAffine::new(pk_op_x, pk_op_y);

    let iss: Fr = {
        let path = crs_dir.join("auth_iss.bin");
        let mut f = BufReader::new(fs::File::open(&path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", path.display(), e)));
        serialization::read_fr(&mut f).unwrap()
    };

    // Compute t_exp
    let t_exp: Fr = match &t_exp_str {
        Some(s) => Fr::from(s.parse::<u64>().unwrap()),
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_secs();
            let exp = now + 3600;
            eprintln!("[token_issue] Using default t_exp = {} (now + 3600)", exp);
            Fr::from(exp)
        }
    };

    // Issue token
    let t0 = Instant::now();

    let sub = pack_email_to_field(&email);

    eprintln!("[token_issue] Issuing token for: {}", email);

    let token = token_issue(&mut rng, &sk_op, &pk_op, &sub, &iss, &t_exp);

    let issue_time = t0.elapsed();
    eprintln!("[token_issue] Token issued in {:.3?}", issue_time);

    // Verify locally
    assert!(token_verify(&pk_op, &token), "Token verification failed!");
    eprintln!("[token_issue] Token self-verification: PASS");

    // Save token
    {
        let mut f = std::io::BufWriter::new(fs::File::create(&output_file).unwrap());
        write_zk_token(&mut f, &token).unwrap();
    }
    let tok_size = fs::metadata(&output_file).unwrap().len();
    eprintln!("[token_issue] Token written to {} ({} bytes)", output_file.display(), tok_size);

    // JSON output
    use ark_serialize::CanonicalSerialize;
    let fr_to_b64 = |f: &Fr| -> String {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf).unwrap();
        base64_encode(&buf)
    };

    println!("{{");
    println!("  \"email\": \"{}\",", email);
    println!("  \"sub\": \"{}\",", fr_to_b64(&sub));
    println!("  \"iss\": \"{}\",", fr_to_b64(&iss));
    println!("  \"t_exp\": \"{}\",", fr_to_b64(&t_exp));
    println!("  \"token_file\": \"{}\",", output_file.display());
    println!("  \"token_size_bytes\": {},", tok_size);
    println!("  \"issue_time_ms\": {:.3}", issue_time.as_secs_f64() * 1000.0);
    println!("}}");
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char); }
        else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(triple & 0x3F) as usize] as char); }
        else { result.push('='); }
    }
    result
}
