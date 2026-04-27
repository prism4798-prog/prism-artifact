//! Prover: Generate a ZK membership proof for an outgoing email.
//! Alice's Nodemailer calls this before sending.

use accumulator::group::Rsa2048;
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::commitments::Commitment;
use cpsnarks_set::protocols::hash_to_prime::snark_hash::{
    poseidon_config_for_test, PoseidonProtocol,
};
use cpsnarks_set::protocols::membership;
use cpsnarks_set::protocols::membership::transcript::TranscriptVerifierChannel;
use cpsnarks_set::serialization;
use cpsnarks_set::utils::bigint_to_integer;
use merlin::Transcript;
use rand::thread_rng;
use rug::integer::IsPrime;
use rug::rand::RandState;
use rug::Integer;
use std::cell::RefCell;
use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

fn to_b64(data: &[u8]) -> String {
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

fn fr_to_b64(f: &Fr) -> String {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).unwrap();
    to_b64(&buf)
}

/// Compute hash-to-prime with custom (u_x, u_y) — must match setup.
fn hash_to_prime_with_key(u_x: &Fr, u_y: &Fr, hash_to_prime_bits: u16) -> (Integer, u64) {
    let config = poseidon_config_for_test::<Fr>();
    for index in 0u64..1 << 16 {
        let mut sponge = PoseidonSponge::new(&config);
        sponge.absorb(u_x);
        sponge.absorb(u_y);
        sponge.absorb(&Fr::from(index));
        let h: Fr = sponge.squeeze_field_elements(1)[0];
        let h_bits = h.into_bigint().to_bits_be();
        let skip = h_bits.len() - (hash_to_prime_bits as usize - 1);
        let hash_bits: Vec<bool> = [vec![true].as_slice(), &h_bits[skip..]].concat();
        let element = Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_be(&hash_bits)).unwrap();
        let integer = bigint_to_integer::<G1Projective>(&element);
        if integer.is_probably_prime(64) != IsPrime::No {
            return (integer, index);
        }
    }
    panic!("hash_to_prime failed");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut crs_dir = PathBuf::from("./zkp-data");
    let mut sender_email = String::from("alice@senderdomain.org");
    let mut recipient_email = String::from("bob@receiverdomain.org");
    let mut output_file = None;
    let mut ca_id = String::from("senderdomain.org");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--crs-dir" => { i += 1; crs_dir = PathBuf::from(&args[i]); }
            "--sender" => { i += 1; sender_email = args[i].clone(); }
            "--recipient" => { i += 1; recipient_email = args[i].clone(); }
            "--output" | "-o" => { i += 1; output_file = Some(PathBuf::from(&args[i])); }
            "--ca" => { i += 1; ca_id = args[i].clone(); }
            "--help" | "-h" => {
                eprintln!("Usage: prover [--crs-dir DIR] [--sender EMAIL] [--recipient EMAIL] [--output FILE] [--ca ID]");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    eprintln!("[prover] Loading CRS...");
    let t0 = Instant::now();

    // Load CRS
    let crs: serialization::FullCRS = {
        let crs_path = crs_dir.join("crs.bin");
        let mut f = BufReader::new(fs::File::open(&crs_path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", crs_path.display(), e)));
        serialization::read_crs(&mut f).expect("Failed to deserialize CRS")
    };
    eprintln!("[prover] CRS loaded in {:.1?}", t0.elapsed());

    // Load accumulator
    let acc_value = {
        let acc_path = crs_dir.join("accumulator.bin");
        let mut f = BufReader::new(fs::File::open(&acc_path).expect("open accumulator"));
        serialization::read_accumulator(&mut f).expect("deserialize accumulator")
    };

    // Load recipient's witness file: sk, u_x, u_y, prime, witness_w
    let witness_path = crs_dir.join("witnesses").join(format!("{}.bin", recipient_email));
    let (recipient_sk, u_x, u_y, hashed_prime, witness_w) = {
        let mut f = BufReader::new(fs::File::open(&witness_path)
            .unwrap_or_else(|e| panic!("Cannot open {}: {}", witness_path.display(), e)));
        let sk = serialization::read_fr(&mut f).unwrap();
        let ux = serialization::read_fr(&mut f).unwrap();
        let uy = serialization::read_fr(&mut f).unwrap();
        let prime = serialization::read_integer(&mut f).unwrap();
        let w = serialization::read_rsa_elem(&mut f).unwrap();
        (sk, ux, uy, prime, w)
    };
    eprintln!("[prover] Witness loaded for {}", recipient_email);

    // Re-derive the hashed prime from (u_x, u_y) to verify consistency
    let (recomputed_prime, _) = hash_to_prime_with_key(&u_x, &u_y, crs.parameters.hash_to_prime_bits);
    assert_eq!(recomputed_prime, hashed_prime, "Prime mismatch — witness file corrupted?");

    // Pedersen commitment randomness
    let t_commit = Instant::now();
    let randomness = Integer::from(5); // TODO: random in production

    // Commit to the hashed prime
    let commitment = crs.crs_modeq.pedersen_commitment_parameters
        .commit(&hashed_prime, &randomness).expect("Pedersen commit failed");
    let commit_time = t_commit.elapsed();
    eprintln!("[prover] Pedersen commitment: {:.3?}", commit_time);
    // ============================================================
    // Native computation of ciphertext C
    // ============================================================
    let t_enc = Instant::now();
    let poseidon_config = poseidon_config_for_test::<Fr>();
    let salt = Fr::from(12345u64);
    let info = Fr::from(67890u64);
    let nc = Fr::from(1u64); // TODO: random nonce per email in production
    let email_bytes = sender_email.as_bytes().to_vec();
    assert!(email_bytes.len() <= 31, "Sender email too long ({} bytes, max 31)", email_bytes.len());

    // Generate ephemeral ECDH key
    let mut rng2 = thread_rng();
    let e_sec = Fr::rand(&mut rng2);

    // Recipient's public key point
    let recipient_pubkey = ark_ed_on_bls12_381::EdwardsAffine::new(u_x, u_y);

    // EC DH shared secret: e_sec * recipient_pubkey
    let shared_key = recipient_pubkey.mul_bigint(e_sec.into_bigint());
    let shared_affine = shared_key.into_affine();

    // Ephemeral public key: e_sec * generator (Bob needs this to derive shared secret)
    let gen = ark_ed_on_bls12_381::EdwardsAffine::generator();
    let e_pub = gen.mul_bigint(e_sec.into_bigint()).into_affine();

    // KDF: K_pos = Poseidon(salt, x, y, info)
    let mut kdf_sponge = PoseidonSponge::new(&poseidon_config);
    kdf_sponge.absorb(&salt);
    kdf_sponge.absorb(&shared_affine.x);
    kdf_sponge.absorb(&shared_affine.y);
    kdf_sponge.absorb(&info);
    let k_pos: Fr = kdf_sponge.squeeze_field_elements(1)[0];

    // Byte packing: m = sum b_i * 256^i
    let mut m_native = Fr::from(0u64);
    let mut power = Fr::from(1u64);
    for i in 0..31usize {
        let byte_val = if i < email_bytes.len() { Fr::from(email_bytes[i] as u64) } else { Fr::from(0u64) };
        m_native += byte_val * power;
        power *= Fr::from(256u64);
    }

    // Keystream: S = Poseidon(salt, K_pos, nc)
    let mut enc_sponge = PoseidonSponge::new(&poseidon_config);
    enc_sponge.absorb(&salt);
    enc_sponge.absorb(&k_pos);
    enc_sponge.absorb(&nc);
    let keystreams: Vec<Fr> = enc_sponge.squeeze_field_elements(2);
    let sender_keystream = keystreams[0];
    let recipient_keystream = keystreams[1];

    // Encryption: C = m + S
    let ciphertext_native = m_native + sender_keystream;
    eprintln!("[prover] Native ciphertext computed");

    // Encrypt recipient identity (same keystream + different offset)
    let recipient_bytes = recipient_email.as_bytes().to_vec();
    assert!(recipient_bytes.len() <= 31, "Recipient email too long");
    let mut m_recv = Fr::from(0u64);
    let mut power_recv = Fr::from(1u64);
    for i in 0..31usize {
        let byte_val = if i < recipient_bytes.len() { Fr::from(recipient_bytes[i] as u64) } else { Fr::from(0u64) };
        m_recv += byte_val * power_recv;
        power_recv *= Fr::from(256u64);
    }
    let recipient_ciphertext = m_recv + recipient_keystream;
    let enc_time = t_enc.elapsed();
    eprintln!("[prover] Metadata encryption (ECDH+KDF+encrypt both): {:.3?}", enc_time);
    // ============================================================
    // Generate membership proof
    // ============================================================
    eprintln!("[prover] Generating proof...");
    let t1 = Instant::now();

    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(42));

    let proof_transcript = RefCell::new(Transcript::new(b"membership"));
    let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);

    let statement = membership::Statement {
        c_e_q: commitment,
        c_p: acc_value,
        nc: Some(nc),
        ciphertext: Some(ciphertext_native),
    };

    // The membership witness uses the raw value (email-derived Integer)
    // that hash_to_prime will re-hash inside prove().
    // But PoseidonProtocol::hash_to_prime uses the generator, not our custom key.
    // So we pass u_y so the prove() path can use it.
    //
    // Looking at PoseidonProtocol::prove():
    //   - It calls self.hash_to_prime(&witness.e) which uses generator (u_x, u_y)
    //   - Then checks witness.u_y: if Some, uses (witness.e as u_x, u_y)
    //
    // We need witness.e to be the x-coordinate integer, and u_y to be y-coordinate.
    let u_x_integer = bigint_to_integer::<G1Projective>(&u_x);
    let u_y_integer = bigint_to_integer::<G1Projective>(&u_y);

    let witness = membership::Witness {
        e: u_x_integer,
        r_q: randomness,
        w: witness_w,
        e_sec: Some(e_sec),
        email_bytes: Some(email_bytes),
        u_y: Some(u_y_integer),
    };

    let protocol = membership::Protocol::<
        Rsa2048, G1Projective, PoseidonProtocol<Bls12_381>,
    >::from_crs(&crs);

    protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &witness)
        .expect("Proof generation failed");

    let proof = verifier_channel.proof().expect("Extract proof");
    let prove_time = t1.elapsed();
    eprintln!("[prover] Proof generated in {:.3?}", prove_time);

    // ============================================================
    // Serialize
    // ============================================================
    let t_ser = Instant::now();
    let mut proof_bytes = Vec::new();
    serialization::write_proof(&mut proof_bytes, &proof).unwrap();
    let mut stmt_bytes = Vec::new();
    serialization::write_statement(&mut stmt_bytes, &statement).unwrap();
    // Detailed size breakdown
    eprintln!("\n=== PROOF BUNDLE SIZE BREAKDOWN ===");
    
    // Measure each proof component individually
    let mut buf = Vec::new();
    
    // c_e
    buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.c_e).unwrap();
    eprintln!("c_e (integer commitment):        {} bytes", buf.len());
    
    // CPRoot Message1
    buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_root.message1.c_w).unwrap();
    let cw = buf.len(); buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_root.message1.c_r).unwrap();
    eprintln!("CPRoot Msg1 (c_w, c_r):          {} bytes", cw + buf.len());
    
    // CPRoot Message2
    buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_root.message2.alpha1).unwrap();
    let a1 = buf.len(); buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_root.message2.alpha2).unwrap();
    let a2 = buf.len(); buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_root.message2.alpha3).unwrap();
    let a3 = buf.len(); buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_root.message2.alpha4).unwrap();
    eprintln!("CPRoot Msg2 (α1..α4):            {} bytes", a1 + a2 + a3 + buf.len());
    
    // CPRoot Message3
    buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_root.message3.s_e).unwrap();
    let s1 = buf.len(); buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_root.message3.s_r).unwrap();
    let s2 = buf.len(); buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_root.message3.s_r_2).unwrap();
    let s3 = buf.len(); buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_root.message3.s_r_3).unwrap();
    let s4 = buf.len(); buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_root.message3.s_beta).unwrap();
    let s5 = buf.len(); buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_root.message3.s_delta).unwrap();
    eprintln!("CPRoot Msg3 (6 integers):        {} bytes", s1+s2+s3+s4+s5+buf.len());
    
    // CPmodEq Message1
    buf.clear();
    serialization::write_rsa_elem(&mut buf, &proof.proof_modeq.message1.alpha1).unwrap();
    let ma1 = buf.len(); buf.clear();
    serialization::write_g1(&mut buf, &proof.proof_modeq.message1.alpha2).unwrap();
    eprintln!("CPmodEq Msg1 (α1, α2):           {} bytes", ma1 + buf.len());
    
    // CPmodEq Message2
    buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_modeq.message2.s_e).unwrap();
    let me1 = buf.len(); buf.clear();
    serialization::write_integer(&mut buf, &proof.proof_modeq.message2.s_r).unwrap();
    let me2 = buf.len(); buf.clear();
    serialization::write_fr(&mut buf, &proof.proof_modeq.message2.s_r_q).unwrap();
    eprintln!("CPmodEq Msg2 (s_e, s_r, s_r_q):  {} bytes", me1+me2+buf.len());
    
    // CP_IdEnc (LegoGroth16)
    buf.clear();
    use ark_serialize::CanonicalSerialize;
    proof.proof_hash_to_prime.serialize_compressed(&mut buf).unwrap();
    eprintln!("CP_IdEnc (LegoGroth16):           {} bytes", buf.len());
    
    eprintln!("---");
    eprintln!("Proof total (with magic+framing): {} bytes", proof_bytes.len());
    
    // Statement breakdown
    buf.clear();
    serialization::write_rsa_elem(&mut buf, &statement.c_p).unwrap();
    eprintln!("Statement c_p (accumulator):      {} bytes", buf.len());
    buf.clear();
    serialization::write_g1(&mut buf, &statement.c_e_q).unwrap();
    eprintln!("Statement c_e_q (Pedersen):       {} bytes", buf.len());
    buf.clear();
    serialization::write_fr(&mut buf, &statement.nc.unwrap()).unwrap();
    eprintln!("Statement nc (nonce):             {} bytes", buf.len());
    buf.clear();
    serialization::write_fr(&mut buf, &statement.ciphertext.unwrap()).unwrap();
    eprintln!("Statement C (ciphertext):         {} bytes", buf.len());
    eprintln!("Statement total (with framing):   {} bytes", stmt_bytes.len());
    eprintln!("---");
    eprintln!("BUNDLE TOTAL:                     {} bytes", proof_bytes.len() + stmt_bytes.len());
    eprintln!("=== END BREAKDOWN ===\n");

    let mut bundle_bytes = Vec::new();
    bundle_bytes.extend_from_slice(&proof_bytes);
    bundle_bytes.extend_from_slice(&stmt_bytes);

    let ser_time = t_ser.elapsed();
    eprintln!("[prover] Serialization: {:.3?}", ser_time);
    eprintln!("[prover] === TOTAL (commit+encrypt+prove+serialize): {:.3?} ===", 
        commit_time + enc_time + prove_time + ser_time);

    if let Some(ref out_path) = output_file {
        let mut f = BufWriter::new(fs::File::create(out_path).expect("create output file"));
        f.write_all(&bundle_bytes).unwrap();
        eprintln!("[prover] Bundle written to {} ({} bytes)", out_path.display(), bundle_bytes.len());
    }

    // JSON to stdout
    let ciphertext_b64 = fr_to_b64(&ciphertext_native);
    let nonce_b64 = fr_to_b64(&nc);
    let commitment_b64 = {
        let mut buf = Vec::new();
        statement.c_e_q.into_affine().serialize_compressed(&mut buf).unwrap();
        to_b64(&buf)
    };
    let proof_b64 = to_b64(&bundle_bytes);

    println!("{{");
    println!("  \"ciphertext\": \"{}\",", ciphertext_b64);
    println!("  \"nonce\": \"{}\",", nonce_b64);
    println!("  \"commitment\": \"{}\",", commitment_b64);
    println!("  \"ephemeral_pub_x\": \"{}\",", fr_to_b64(&e_pub.x));
    println!("  \"ephemeral_pub_y\": \"{}\",", fr_to_b64(&e_pub.y));
    println!("  \"proof_b64\": \"{}\",", proof_b64);
    println!("  \"ca_id\": \"{}\",", ca_id);
    println!("  \"prove_time_ms\": {},", prove_time.as_millis());
    println!("  \"commit_time_ms\": {},", commit_time.as_micros() as f64 / 1000.0);
    println!("  \"encrypt_time_ms\": {},", enc_time.as_micros() as f64 / 1000.0);
    println!("  \"serialize_time_ms\": {},", ser_time.as_micros() as f64 / 1000.0);
    println!("  \"proof_size_bytes\": {},", bundle_bytes.len());
    println!("  \"sender\": \"{}\",", sender_email);
    println!("  \"recipient_ciphertext\": \"{}\",", fr_to_b64(&recipient_ciphertext));
    println!("  \"keystream\": \"{}\"", fr_to_b64(&sender_keystream));
    println!("}}");
}
