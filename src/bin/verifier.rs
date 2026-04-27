//! Verifier: Verify a ZK membership proof attached to an incoming email.
//!
//! The receiver MTA (Postfix milter) calls this binary when an email arrives
//! with ZK proof headers. It verifies the proof and outputs accept/reject.
//!
//! Usage:
//!   cargo run --bin verifier --features arkworks -- \
//!     --crs-dir ./zkp-data \
//!     --proof proof-bundle.bin
//!
//! Or pipe the proof+statement bytes via stdin:
//!   cat proof-bundle.bin | cargo run --bin verifier -- --crs-dir ./zkp-data --stdin
//!
//! Exit codes:
//!   0 = proof valid (ACCEPT)
//!   1 = proof invalid (REJECT)
//!   2 = error (malformed input, missing files, etc.)

use accumulator::group::Rsa2048;
use ark_bls12_381::{Bls12_381, G1Projective};
use cpsnarks_set::protocols::hash_to_prime::snark_hash::PoseidonProtocol;
use cpsnarks_set::protocols::membership;
use cpsnarks_set::protocols::membership::transcript::TranscriptProverChannel;
use cpsnarks_set::serialization;
use merlin::Transcript;
use std::cell::RefCell;
use std::fs;
use std::io::{self, BufReader, Read};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut crs_dir = PathBuf::from("./zkp-data");
    let mut proof_file = None;
    let mut use_stdin = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--crs-dir" => {
                i += 1;
                crs_dir = PathBuf::from(&args[i]);
            }
            "--proof" => {
                i += 1;
                proof_file = Some(PathBuf::from(&args[i]));
            }
            "--stdin" => {
                use_stdin = true;
            }
            "--help" | "-h" => {
                println!("Usage: verifier [OPTIONS]");
                println!();
                println!("  --crs-dir DIR    Directory with crs.bin (or vk.bin), accumulator.bin");
                println!("  --proof FILE     Proof bundle file (output of prover)");
                println!("  --stdin          Read proof bundle from stdin");
                println!();
                println!("Exit codes: 0=ACCEPT, 1=REJECT, 2=ERROR");
                return;
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if proof_file.is_none() && !use_stdin {
        eprintln!("[verifier] ERROR: specify --proof FILE or --stdin");
        std::process::exit(2);
    }

    // ============================================================
    // Load CRS (full CRS for now — in production, vk.bin suffices
    // but we need the full CRS for transcript reconstruction)
    // ============================================================
    eprintln!("[verifier] Loading CRS from {}...", crs_dir.display());
    let t0 = Instant::now();

    let crs_path = crs_dir.join("crs.bin");
    let crs: serialization::FullCRS = {
        let mut f = BufReader::new(
            fs::File::open(&crs_path)
                .unwrap_or_else(|e| {
                    eprintln!("[verifier] ERROR: Cannot open {}: {}", crs_path.display(), e);
                    std::process::exit(2);
                }),
        );
        match serialization::read_crs(&mut f) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[verifier] ERROR: Failed to deserialize CRS: {}", e);
                std::process::exit(2);
            }
        }
    };
    eprintln!("[verifier] CRS loaded in {:.1?}", t0.elapsed());

    // ============================================================
    // Read proof + statement bundle
    // ============================================================
    let bundle_bytes: Vec<u8> = if use_stdin {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
            eprintln!("[verifier] ERROR: stdin read: {}", e);
            std::process::exit(2);
        });
        buf
    } else {
        let path = proof_file.unwrap();
        fs::read(&path).unwrap_or_else(|e| {
            eprintln!("[verifier] ERROR: Cannot read {}: {}", path.display(), e);
            std::process::exit(2);
        })
    };

    eprintln!("[verifier] Bundle size: {} bytes", bundle_bytes.len());

    // Parse proof then statement from concatenated bytes
    let mut cursor = &bundle_bytes[..];

    let proof: serialization::FullProof = match serialization::read_proof(&mut cursor) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[verifier] ERROR: Failed to parse proof: {}", e);
            std::process::exit(2);
        }
    };

    let statement: serialization::FullStatement = match serialization::read_statement(&mut cursor) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[verifier] ERROR: Failed to parse statement: {}", e);
            std::process::exit(2);
        }
    };

    eprintln!(
        "[verifier] Proof parsed. nc={}, ciphertext={}",
        if statement.nc.is_some() { "present" } else { "none" },
        if statement.ciphertext.is_some() { "present" } else { "none" },
    );

    // ============================================================
    // Verify
    // ============================================================
    eprintln!("[verifier] Verifying proof (CPRoot + CPmodEq + CP_IdEnc)...");
    let t1 = Instant::now();

    let protocol = membership::Protocol::<
        Rsa2048,
        G1Projective,
        PoseidonProtocol<Bls12_381>,
    >::from_crs(&crs);

    // Reconstruct the verification transcript and prover channel
    let verification_transcript = RefCell::new(Transcript::new(b"membership"));
    let mut prover_channel =
        TranscriptProverChannel::new(&crs, &verification_transcript, &proof);

    match protocol.verify(&mut prover_channel, &statement) {
        Ok(()) => {
            let verify_time = t1.elapsed();
            eprintln!("[verifier] ACCEPT — proof valid ({:.1?})", verify_time);

            // Output JSON result to stdout
            println!("{{");
            println!("  \"result\": \"ACCEPT\",");
            println!("  \"verify_time_ms\": {}", verify_time.as_millis());
            println!("}}");

            std::process::exit(0);
        }
        Err(e) => {
            let verify_time = t1.elapsed();
            eprintln!(
                "[verifier] REJECT — proof invalid ({:.1?}): {:?}",
                verify_time, e
            );

            println!("{{");
            println!("  \"result\": \"REJECT\",");
            println!("  \"error\": \"{:?}\",", e);
            println!("  \"verify_time_ms\": {}", verify_time.as_millis());
            println!("}}");

            std::process::exit(1);
        }
    }
}
