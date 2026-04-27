//! Auth Setup: Generate Keycloak's EdDSA keypair + Groth16 CRS for Ckt_auth.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::thread_rng;
use std::fs;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Instant;
use ark_ec::AffineRepr;

use cpsnarks_set::protocols::zkauth::{
    eddsa_keygen, compute_iss, AuthCircuit, AuthPublicInputs, AuthPrivateWitnesses,
};
use cpsnarks_set::serialization;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out_dir = PathBuf::from("./zkp-data");
    let mut domain = String::from("senderdomain.org");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out-dir" => { i += 1; out_dir = PathBuf::from(&args[i]); }
            "--domain" => { i += 1; domain = args[i].clone(); }
            "--help" | "-h" => {
                eprintln!("Usage: auth_setup [--out-dir DIR] [--domain DOMAIN]");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    fs::create_dir_all(&out_dir).expect("create out dir");

    eprintln!("[auth_setup] Generating Keycloak EdDSA keypair...");
    let mut rng = thread_rng();
    let kp = eddsa_keygen(&mut rng);
    let iss = compute_iss(&domain);

    eprintln!("[auth_setup] pk_OP = ({}, {})",
        &format!("{:?}", kp.pk.x)[..20], &format!("{:?}", kp.pk.y)[..20]);

    // Save secret key
    let sk_path = out_dir.join("auth_sk_op.bin");
    {
        let mut f = BufWriter::new(fs::File::create(&sk_path).unwrap());
        serialization::write_fr(&mut f, &kp.sk).unwrap();
    }
    eprintln!("[auth_setup] Secret key → {}", sk_path.display());

    // Save public key
    let pk_path = out_dir.join("auth_pk_op.bin");
    {
        let mut f = BufWriter::new(fs::File::create(&pk_path).unwrap());
        serialization::write_fr(&mut f, &kp.pk.x).unwrap();
        serialization::write_fr(&mut f, &kp.pk.y).unwrap();
    }
    eprintln!("[auth_setup] Public key → {}", pk_path.display());

    // Save iss
    let iss_path = out_dir.join("auth_iss.bin");
    {
        let mut f = BufWriter::new(fs::File::create(&iss_path).unwrap());
        serialization::write_fr(&mut f, &iss).unwrap();
    }

    // Generate Groth16 CRS
    eprintln!("[auth_setup] Generating Groth16 CRS for Ckt_auth...");
    let t0 = Instant::now();

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

    let (pk_groth, vk_groth) = Groth16::<Bls12_381>::circuit_specific_setup(
        dummy_circuit, &mut rng,
    ).expect("Groth16 setup failed");

    eprintln!("[auth_setup] CRS generated in {:.1?}", t0.elapsed());

    // Save proving key
    let crs_path = out_dir.join("auth_crs.bin");
    {
        let mut buf = Vec::new();
        pk_groth.serialize_compressed(&mut buf).unwrap();
        fs::write(&crs_path, &buf).unwrap();
        eprintln!("[auth_setup] Proving key → {} ({} bytes)",
            crs_path.display(), buf.len());
    }

    // Save verification key
    let vk_path = out_dir.join("auth_vk.bin");
    {
        let mut buf = Vec::new();
        vk_groth.serialize_compressed(&mut buf).unwrap();
        fs::write(&vk_path, &buf).unwrap();
        eprintln!("[auth_setup] Verification key → {} ({} bytes)",
            vk_path.display(), buf.len());
    }

    eprintln!("\n=== Auth Setup Complete ===");
    eprintln!("Domain: {}", domain);
    eprintln!("Files:");
    eprintln!("  auth_sk_op.bin  — Keycloak's secret key (KEEP SECURE)");
    eprintln!("  auth_pk_op.bin  — Keycloak's public key (distribute)");
    eprintln!("  auth_iss.bin    — Issuer field element");
    eprintln!("  auth_crs.bin    — Groth16 proving key (users)");
    eprintln!("  auth_vk.bin     — Groth16 verification key (sender MTA)");
}
