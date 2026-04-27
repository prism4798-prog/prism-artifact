//! Decrypt: Bob scans the common mailbox, tries to decrypt each email
//! with his JubJub private key. If recipient matches, moves to his mailbox.
//!
//! Usage:
//!   ./decrypt --key bob_secret.bin --inbox /home/ppe/Maildir/new --mailbox /home/bob/Maildir/new

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fs;
use std::io::{BufReader, Read};
use std::path::PathBuf;

fn poseidon_config() -> ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr> {
    cpsnarks_set::protocols::hash_to_prime::snark_hash::poseidon_config_for_test::<Fr>()
}

fn fr_from_b64(s: &str) -> Option<Fr> {
    let bytes = base64_decode(s.trim())?;
    Fr::deserialize_compressed(&bytes[..]).ok()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let table: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .to_vec();
    let mut out = Vec::new();
    let clean: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 { break; }
        let a = table.iter().position(|&c| c == chunk[0]).unwrap_or(0) as u32;
        let b = table.iter().position(|&c| c == chunk[1]).unwrap_or(0) as u32;
        let c = if chunk.len() > 2 && chunk[2] != b'=' {
            table.iter().position(|&x| x == chunk[2]).unwrap_or(0) as u32
        } else { 0 };
        let d = if chunk.len() > 3 && chunk[3] != b'=' {
            table.iter().position(|&x| x == chunk[3]).unwrap_or(0) as u32
        } else { 0 };
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' { out.push(((triple >> 8) & 0xFF) as u8); }
        if chunk.len() > 3 && chunk[3] != b'=' { out.push((triple & 0xFF) as u8); }
    }
    Some(out)
}

/// Decrypt a ciphertext field element back to email bytes
fn decrypt_to_string(ciphertext: &Fr, keystream: &Fr) -> String {
    let m = *ciphertext - *keystream;
    // Unpack: m = sum b_i * 256^i
    let m_bigint = m.into_bigint();
    let mut m_bytes = vec![0u8; 32];
    // Convert to little-endian bytes
    let le_limbs = m_bigint.as_ref(); // u64 limbs, little-endian
    for (i, limb) in le_limbs.iter().enumerate() {
        for j in 0..8 {
            if i * 8 + j < 32 {
                m_bytes[i * 8 + j] = ((limb >> (j * 8)) & 0xFF) as u8;
            }
        }
    }
    // Take bytes until null
    let end = m_bytes.iter().position(|&b| b == 0).unwrap_or(31);
    String::from_utf8_lossy(&m_bytes[..end]).to_string()
}

fn extract_header(content: &str, header: &str) -> Option<String> {
    let lower_header = header.to_lowercase();
    let mut result = String::new();
    let mut found = false;
    for line in content.lines() {
        if !found {
            let lower_line = line.to_lowercase();
            if lower_line.starts_with(&format!("{}:", lower_header)) {
                let val = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                result.push_str(val);
                found = true;
            }
        } else {
            // Continuation lines start with space or tab
            if line.starts_with(' ') || line.starts_with('\t') {
                result.push_str(line.trim());
            } else {
                break;
            }
        }
    }
    if found && !result.is_empty() { Some(result) } else { None }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut key_file = PathBuf::from("bob_key.bin");
    let mut inbox = PathBuf::from("/home/ppe/Maildir/new");
    let mut mailbox = PathBuf::from("/home/bob/Maildir/new");
    let mut bob_email = String::from("bob@receiverdomain.org");
    let mut dry_run = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => { i += 1; key_file = PathBuf::from(&args[i]); }
            "--inbox" => { i += 1; inbox = PathBuf::from(&args[i]); }
            "--mailbox" => { i += 1; mailbox = PathBuf::from(&args[i]); }
            "--email" => { i += 1; bob_email = args[i].clone(); }
            "--dry-run" => { dry_run = true; }
            "--help" | "-h" => {
                eprintln!("Usage: decrypt [--key FILE] [--inbox DIR] [--mailbox DIR] [--email ADDR] [--dry-run]");
                return;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    // Load Bob's JubJub secret key
    let bob_sk: Fr = {
        let mut f = BufReader::new(fs::File::open(&key_file)
            .unwrap_or_else(|e| panic!("Cannot open key {}: {}", key_file.display(), e)));
        cpsnarks_set::serialization::read_fr(&mut f).expect("read secret key")
    };
    eprintln!("[decrypt] Loaded secret key from {}", key_file.display());

    let config = poseidon_config();
    let salt = Fr::from(12345u64);
    let info = Fr::from(67890u64);

    // Scan inbox
    let entries = fs::read_dir(&inbox).unwrap_or_else(|e| panic!("Cannot read {}: {}", inbox.display(), e));
    let mut found = 0;
    let mut moved = 0;

    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() { continue; }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Extract required headers
        let eph_x_b64 = match extract_header(&content, "X-Zkp-Eph-Pub-X") { Some(v) => v, None => continue };
        let eph_y_b64 = match extract_header(&content, "X-Zkp-Eph-Pub-Y") { Some(v) => v, None => continue };
        let ciphertext_b64 = match extract_header(&content, "X-Zkp-Ciphertext") { Some(v) => v, None => continue };
        let recv_ct_b64 = match extract_header(&content, "X-Zkp-Recipient-Ciphertext") { Some(v) => v, None => continue };
        let nonce_b64 = match extract_header(&content, "X-Zkp-Nonce") { Some(v) => v, None => continue };

        found += 1;

        // Parse field elements
        let eph_x = match fr_from_b64(&eph_x_b64) { Some(v) => v, None => continue };
        let eph_y = match fr_from_b64(&eph_y_b64) { Some(v) => v, None => continue };
        let sender_ct = match fr_from_b64(&ciphertext_b64) { Some(v) => v, None => continue };
        let recv_ct = match fr_from_b64(&recv_ct_b64) { Some(v) => v, None => continue };
        let nc = match fr_from_b64(&nonce_b64) { Some(v) => v, None => continue };

        // ECDH: shared = bob_sk * ephemeral_pub
        let eph_point = ark_ed_on_bls12_381::EdwardsAffine::new(eph_x, eph_y);
        let shared = eph_point.mul_bigint(bob_sk.into_bigint()).into_affine();

        // KDF: K_pos = Poseidon(salt, shared.x, shared.y, info)
        let mut kdf_sponge = PoseidonSponge::new(&config);
        kdf_sponge.absorb(&salt);
        kdf_sponge.absorb(&shared.x);
        kdf_sponge.absorb(&shared.y);
        kdf_sponge.absorb(&info);
        let k_pos: Fr = kdf_sponge.squeeze_field_elements(1)[0];

        // Keystream: S = Poseidon(salt, K_pos, nc)
        let mut enc_sponge = PoseidonSponge::new(&config);
        enc_sponge.absorb(&salt);
        enc_sponge.absorb(&k_pos);
        enc_sponge.absorb(&nc);
        let keystreams: Vec<Fr> = enc_sponge.squeeze_field_elements(2);
        let sender_keystream = keystreams[0];
        let recipient_keystream = keystreams[1];

        // Decrypt recipient
        let decrypted_recipient = decrypt_to_string(&recv_ct, &recipient_keystream);
        // Decrypt sender
        let decrypted_sender = decrypt_to_string(&sender_ct, &sender_keystream);

        let filename = path.file_name().unwrap().to_string_lossy();

        if decrypted_recipient == bob_email {
            eprintln!("[decrypt] {} → FOR ME! From: {}, To: {}", filename, decrypted_sender, decrypted_recipient);
            if !dry_run {
                let dest = mailbox.join(path.file_name().unwrap());
                fs::copy(&path, &dest).unwrap_or_else(|e| panic!("copy to mailbox: {}", e));
                fs::remove_file(&path).unwrap_or_else(|e| eprintln!("  warning: could not remove original: {}", e));
                eprintln!("[decrypt] Moved to {}", dest.display());
            }
            moved += 1;
        } else {
            eprintln!("[decrypt] {} → not for me (decrypted to: {})", filename, decrypted_recipient);
        }
    }

    eprintln!("[decrypt] Scanned {} ZKP emails, {} for {}", found, moved, bob_email);
}