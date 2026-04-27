//! Serialization helpers for CRS, proofs, accumulator values, and statements.

use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rug::integer::Order;
use rug::Integer;
use std::io::{self, Read, Write};

use crate::commitments::integer::IntegerCommitment;
use crate::commitments::pedersen::PedersenCommitment;
use crate::parameters::Parameters;
use crate::protocols::hash_to_prime::snark_hash::PoseidonProtocol;
use crate::protocols::membership;
use crate::protocols::modeq;
use crate::protocols::root;

use accumulator::group::{ElemFrom, ElemToBytes, Rsa2048};

// ============================================================
// Primitive helpers
// ============================================================

fn write_bytes<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)
}

fn read_bytes<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_integer<W: Write>(w: &mut W, n: &Integer) -> io::Result<()> {
    let sign: u8 = if *n < 0 { 1 } else { 0 };
    w.write_all(&[sign])?;
    let abs = n.clone().abs();
    let digits = abs.significant_digits::<u8>();
    let mut bytes = vec![0u8; digits];
    abs.write_digits(&mut bytes, Order::MsfBe);
    write_bytes(w, &bytes)
}

pub fn read_integer<R: Read>(r: &mut R) -> io::Result<Integer> {
    let mut sign_buf = [0u8; 1];
    r.read_exact(&mut sign_buf)?;
    let negative = sign_buf[0] == 1;
    let bytes = read_bytes(r)?;
    let mut n = Integer::from(0);
    n.assign_digits(&bytes, Order::MsfBe);
    if negative {
        n = -n;
    }
    Ok(n)
}

// ============================================================
// Rsa2048Elem serialization (uses ElemToBytes / ElemFrom)
// ============================================================

type Rsa2048Elem = <Rsa2048 as accumulator::group::Group>::Elem;

pub fn write_rsa_elem<W: Write>(w: &mut W, elem: &Rsa2048Elem) -> io::Result<()> {
    let bytes = Rsa2048::elem_to_bytes(elem);
    write_bytes(w, &bytes)
}

pub fn read_rsa_elem<R: Read>(r: &mut R) -> io::Result<Rsa2048Elem> {
    let bytes = read_bytes(r)?;
    let mut n = Integer::from(0);
    n.assign_digits(&bytes, Order::MsfBe);
    Ok(Rsa2048::elem(n))
}

// ============================================================
// Ark type helpers
// ============================================================

fn write_ark<W: Write, T: CanonicalSerialize>(w: &mut W, val: &T) -> io::Result<()> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ark serialize: {}", e)))?;
    write_bytes(w, &buf)
}

fn read_ark<R: Read, T: CanonicalDeserialize>(r: &mut R) -> io::Result<T> {
    let buf = read_bytes(r)?;
    T::deserialize_compressed(&buf[..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ark deserialize: {}", e)))
}

fn write_u16<W: Write>(w: &mut W, v: u16) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

pub fn write_fr<W: Write>(w: &mut W, f: &Fr) -> io::Result<()> {
    write_ark(w, f)
}

pub fn read_fr<R: Read>(r: &mut R) -> io::Result<Fr> {
    read_ark(r)
}

pub fn write_g1<W: Write>(w: &mut W, p: &G1Projective) -> io::Result<()> {
    write_ark(w, p)
}

fn read_g1<R: Read>(r: &mut R) -> io::Result<G1Projective> {
    read_ark(r)
}

// ============================================================
// Parameters
// ============================================================

pub fn write_parameters<W: Write>(w: &mut W, p: &Parameters) -> io::Result<()> {
    write_u16(w, p.security_level)?;
    write_u16(w, p.security_zk)?;
    write_u16(w, p.security_soundness)?;
    write_u16(w, p.hash_to_prime_bits)?;
    write_u16(w, p.field_size_bits)
}

pub fn read_parameters<R: Read>(r: &mut R) -> io::Result<Parameters> {
    Ok(Parameters {
        security_level: read_u16(r)?,
        security_zk: read_u16(r)?,
        security_soundness: read_u16(r)?,
        hash_to_prime_bits: read_u16(r)?,
        field_size_bits: read_u16(r)?,
    })
}

// ============================================================
// IntegerCommitment<Rsa2048>
// ============================================================

pub fn write_integer_commitment<W: Write>(
    w: &mut W,
    ic: &IntegerCommitment<Rsa2048>,
) -> io::Result<()> {
    write_rsa_elem(w, &ic.g)?;
    write_rsa_elem(w, &ic.h)
}

pub fn read_integer_commitment<R: Read>(r: &mut R) -> io::Result<IntegerCommitment<Rsa2048>> {
    let g = read_rsa_elem(r)?;
    let h = read_rsa_elem(r)?;
    Ok(IntegerCommitment::new(&g, &h))
}

// ============================================================
// PedersenCommitment<G1Projective>
// ============================================================

pub fn write_pedersen_commitment<W: Write>(
    w: &mut W,
    pc: &PedersenCommitment<G1Projective>,
) -> io::Result<()> {
    write_g1(w, &pc.g)?;
    write_g1(w, &pc.h)
}

pub fn read_pedersen_commitment<R: Read>(
    r: &mut R,
) -> io::Result<PedersenCommitment<G1Projective>> {
    let g = read_g1(r)?;
    let h = read_g1(r)?;
    Ok(PedersenCommitment::new(&g, &h))
}

// ============================================================
// LegoGroth16 ProvingKeyWithLink
// ============================================================

pub fn write_proving_key<W: Write>(
    w: &mut W,
    pk: &legogroth16::ProvingKeyWithLink<Bls12_381>,
) -> io::Result<()> {
    write_ark(w, pk)
}

pub fn read_proving_key<R: Read>(
    r: &mut R,
) -> io::Result<legogroth16::ProvingKeyWithLink<Bls12_381>> {
    read_ark(r)
}

// ============================================================
// Full CRS
// ============================================================

pub type FullCRS = membership::CRS<Rsa2048, G1Projective, PoseidonProtocol<Bls12_381>>;

pub fn write_crs<W: Write>(w: &mut W, crs: &FullCRS) -> io::Result<()> {
    w.write_all(b"ZKEMCRS\x01")?;
    write_parameters(w, &crs.parameters)?;
    write_integer_commitment(w, &crs.crs_root.integer_commitment_parameters)?;
    write_integer_commitment(w, &crs.crs_modeq.integer_commitment_parameters)?;
    write_pedersen_commitment(w, &crs.crs_modeq.pedersen_commitment_parameters)?;
    write_pedersen_commitment(w, &crs.crs_hash_to_prime.pedersen_commitment_parameters)?;
    write_proving_key(w, &crs.crs_hash_to_prime.hash_to_prime_parameters)?;
    Ok(())
}

pub fn read_crs<R: Read>(r: &mut R) -> io::Result<FullCRS> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != b"ZKEMCRS\x01" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad CRS magic"));
    }
    let parameters = read_parameters(r)?;
    let root_ic = read_integer_commitment(r)?;
    let modeq_ic = read_integer_commitment(r)?;
    let modeq_pc = read_pedersen_commitment(r)?;
    let htp_pc = read_pedersen_commitment(r)?;
    let htp_pk = read_proving_key(r)?;

    Ok(membership::CRS {
        parameters: parameters.clone(),
        crs_root: crate::protocols::root::CRSRoot {
            parameters: parameters.clone(),
            integer_commitment_parameters: root_ic,
        },
        crs_modeq: crate::protocols::modeq::CRSModEq {
            parameters: parameters.clone(),
            integer_commitment_parameters: modeq_ic,
            pedersen_commitment_parameters: modeq_pc,
        },
        crs_hash_to_prime: crate::protocols::hash_to_prime::CRSHashToPrime {
            parameters: parameters.clone(),
            pedersen_commitment_parameters: htp_pc,
            hash_to_prime_parameters: htp_pk,
        },
    })
}

// ============================================================
// Verifier-only CRS
// ============================================================

pub fn write_verifier_crs<W: Write>(w: &mut W, crs: &FullCRS) -> io::Result<()> {
    w.write_all(b"ZKEMVK\x01\x00")?;
    write_parameters(w, &crs.parameters)?;
    write_integer_commitment(w, &crs.crs_root.integer_commitment_parameters)?;
    write_integer_commitment(w, &crs.crs_modeq.integer_commitment_parameters)?;
    write_pedersen_commitment(w, &crs.crs_modeq.pedersen_commitment_parameters)?;
    write_pedersen_commitment(w, &crs.crs_hash_to_prime.pedersen_commitment_parameters)?;
    write_ark(w, &crs.crs_hash_to_prime.hash_to_prime_parameters.vk)?;
    Ok(())
}

// ============================================================
// Membership Proof
// ============================================================

pub type FullProof = membership::Proof<Rsa2048, G1Projective, PoseidonProtocol<Bls12_381>>;

pub fn write_proof<W: Write>(w: &mut W, proof: &FullProof) -> io::Result<()> {
    w.write_all(b"ZKEMPRF\x01")?;
    write_rsa_elem(w, &proof.c_e)?;
    // Root proof
    write_rsa_elem(w, &proof.proof_root.message1.c_w)?;
    write_rsa_elem(w, &proof.proof_root.message1.c_r)?;
    write_rsa_elem(w, &proof.proof_root.message2.alpha1)?;
    write_rsa_elem(w, &proof.proof_root.message2.alpha2)?;
    write_rsa_elem(w, &proof.proof_root.message2.alpha3)?;
    write_rsa_elem(w, &proof.proof_root.message2.alpha4)?;
    write_integer(w, &proof.proof_root.message3.s_e)?;
    write_integer(w, &proof.proof_root.message3.s_r)?;
    write_integer(w, &proof.proof_root.message3.s_r_2)?;
    write_integer(w, &proof.proof_root.message3.s_r_3)?;
    write_integer(w, &proof.proof_root.message3.s_beta)?;
    write_integer(w, &proof.proof_root.message3.s_delta)?;
    // ModEq proof
    write_rsa_elem(w, &proof.proof_modeq.message1.alpha1)?;
    write_g1(w, &proof.proof_modeq.message1.alpha2)?;
    write_integer(w, &proof.proof_modeq.message2.s_e)?;
    write_integer(w, &proof.proof_modeq.message2.s_r)?;
    write_fr(w, &proof.proof_modeq.message2.s_r_q)?;
    // Hash-to-prime proof
    write_ark(w, &proof.proof_hash_to_prime)?;
    Ok(())
}

pub fn read_proof<R: Read>(r: &mut R) -> io::Result<FullProof> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != b"ZKEMPRF\x01" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad proof magic"));
    }
    let c_e = read_rsa_elem(r)?;
    let proof_root = root::Proof {
        message1: root::Message1 {
            c_w: read_rsa_elem(r)?,
            c_r: read_rsa_elem(r)?,
        },
        message2: root::Message2 {
            alpha1: read_rsa_elem(r)?,
            alpha2: read_rsa_elem(r)?,
            alpha3: read_rsa_elem(r)?,
            alpha4: read_rsa_elem(r)?,
        },
        message3: root::Message3 {
            s_e: read_integer(r)?,
            s_r: read_integer(r)?,
            s_r_2: read_integer(r)?,
            s_r_3: read_integer(r)?,
            s_beta: read_integer(r)?,
            s_delta: read_integer(r)?,
        },
    };
    let proof_modeq = modeq::Proof {
        message1: modeq::Message1 {
            alpha1: read_rsa_elem(r)?,
            alpha2: read_g1(r)?,
        },
        message2: modeq::Message2 {
            s_e: read_integer(r)?,
            s_r: read_integer(r)?,
            s_r_q: read_fr(r)?,
        },
    };
    let proof_hash_to_prime: legogroth16::ProofWithLink<Bls12_381> = read_ark(r)?;

    Ok(membership::Proof {
        c_e,
        proof_root,
        proof_modeq,
        proof_hash_to_prime,
    })
}

// ============================================================
// Statement
// ============================================================

pub type FullStatement = membership::Statement<Rsa2048, G1Projective>;

pub fn write_statement<W: Write>(w: &mut W, stmt: &FullStatement) -> io::Result<()> {
    w.write_all(b"ZKEMSTM\x01")?;
    write_rsa_elem(w, &stmt.c_p)?;
    write_g1(w, &stmt.c_e_q)?;
    match stmt.nc {
        Some(ref nc) => { w.write_all(&[1u8])?; write_fr(w, nc)?; }
        None => w.write_all(&[0u8])?,
    }
    match stmt.ciphertext {
        Some(ref c) => { w.write_all(&[1u8])?; write_fr(w, c)?; }
        None => w.write_all(&[0u8])?,
    }
    Ok(())
}

pub fn read_statement<R: Read>(r: &mut R) -> io::Result<FullStatement> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != b"ZKEMSTM\x01" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad statement magic"));
    }
    let c_p = read_rsa_elem(r)?;
    let c_e_q = read_g1(r)?;
    let mut flag = [0u8; 1];
    r.read_exact(&mut flag)?;
    let nc = if flag[0] == 1 { Some(read_fr(r)?) } else { None };
    r.read_exact(&mut flag)?;
    let ciphertext = if flag[0] == 1 { Some(read_fr(r)?) } else { None };
    Ok(membership::Statement { c_p, c_e_q, nc, ciphertext })
}

// ============================================================
// Accumulator value
// ============================================================

pub fn write_accumulator<W: Write>(w: &mut W, acc: &Rsa2048Elem) -> io::Result<()> {
    w.write_all(b"ZKEMACC\x01")?;
    write_rsa_elem(w, acc)
}

pub fn read_accumulator<R: Read>(r: &mut R) -> io::Result<Rsa2048Elem> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != b"ZKEMACC\x01" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad accumulator magic"));
    }
    read_rsa_elem(r)
}
