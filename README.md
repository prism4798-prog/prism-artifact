# PRISM: Privacy-Preserving Routing with Identity-Shielded Mail

**Artifact for CCS 2026 submission** cycle b

## Overview

PRISM hides sender and recipient identities from outsourced mail
transfer agents (MTAs) while preserving the SMTP wire format and
reusing existing S/MIME and LDAP infrastructure. The system replaces
identity-revealing SMTP AUTH credentials with zero-knowledge proofs
that bind authenticated identities to encrypted email metadata.

This repository contains the cryptographic core of PRISM: three
zero-knowledge circuits, an RSA accumulator-based domain membership
protocol, a ZK-friendly token issuance scheme, and benchmarking
infrastructure. The SMTP integration layer (Node.js, Postfix,
Dovecot) is not included in this artifact.

## Architecture

PRISM composes two algorithms per email:

**Algorithm 1 (Identity-Hiding Header Protocol)** encrypts sender
and recipient identifiers under an ECDH-derived session key and
proves domain membership via three commit-and-prove sub-protocols:

|Sub-protocol|What it proves                                                                               |Proof system                        |
|------------|---------------------------------------------------------------------------------------------|------------------------------------|
|CP_Root     |Recipient’s public key is in the RSA accumulator                                             |Sigma protocol                      |
|CP_modEq    |Integer commitment and Pedersen commitment contain the same value                            |Sigma protocol                      |
|CP_IdEnc    |ECDH key exchange, KDF/PRF derivation, hash-to-prime, and identity encryption are well-formed|LegoGroth16 (6,456 R1CS constraints)|

**Algorithm 2 (Anonymous SMTP Authentication)** replaces bearer-token
SMTP AUTH with a ZK proof of token possession, in two variants:

|Circuit   |Role                   |Proof system|Constraints|
|----------|-----------------------|------------|-----------|
|R_auth^(S)|Sender authentication  |LegoGroth16 |7,266      |
|R_auth^(R)|Receiver authentication|Groth16     |12,295     |

The sender variant produces a Pedersen commitment `c_id'` for
identity binding via commitment equality. The receiver variant
derives the encryption key inside the circuit from the prover’s
private key via ECDH, KDF, and PRF, ensuring only the intended
recipient can generate a valid proof.

## Repository Structure

```
src/
├── protocols/
│   ├── membership/          # RSA accumulator membership proof (CP_Root + CP_modEq + CP_IdEnc)
│   │   └── mod.rs           # Full membership protocol composition
│   ├── root/                # CP_Root: committed element exists in accumulator
│   ├── modeq/               # CP_modEq: integer commitment ≡ Pedersen commitment
│   ├── hash_to_prime/
│   │   └── snark_hash.rs    # CP_IdEnc circuit: ECDH, Poseidon KDF/PRF, hash-to-prime,
│   │                        #   byte packing, identity encryption (6,456 constraints)
│   ├── zkauth.rs            # R_auth circuits: EdDSA token verification, identity binding
│   │                        #   Sender (LegoGroth16, 7,266) + Receiver (Groth16, 12,295)
│   ├── coprime/             # CP_NonMem (non-membership, not used in PRISM)
│   └── nonmembership/       # Non-membership protocol (not used in PRISM)
├── parameters/              # System parameter management
├── utils/
│   └── curve.rs             # Curve utilities for BLS12-381 and JubJub
└── lib.rs

bin/
├── setup.rs                 # CRS generation for all circuits
├── prover.rs                # Full pipeline: membership + auth proof generation
└── verifier.rs              # MTA-side verification

zkp-data/                    # Generated CRS files (created by setup binary)
```

## Cryptographic Primitives

|Primitive             |Instantiation           |Usage                    |
|----------------------|------------------------|-------------------------|
|Pairing curve         |BLS12-381               |SNARK proofs             |
|Embedded curve        |JubJub (ed-on-bls12-381)|EdDSA signatures, ECDH   |
|Hash function         |Poseidon (α=17, width=3)|Token hash, KDF, PRF     |
|Signature             |EdDSA on JubJub         |ZK-friendly token signing|
|Accumulator           |RSA-2048                |Domain membership        |
|Commit-and-prove SNARK|LegoGroth16             |CP_IdEnc, R_auth^(S)     |
|SNARK                 |Groth16 (ark-groth16)   |R_auth^(R)               |
|Key exchange          |ECDH on JubJub          |Session key derivation   |

## Building

**Prerequisites:** Rust nightly, GMP library (for RSA-2048 via `rug`)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build
cargo build --features arkworks --release
```

## Running the Full Pipeline

```bash
# Step 1: Generate CRS (one-time per domain)
./target/release/setup --crs-dir ./zkp-data --num-users 1000

# Step 2: Run prover (generates membership + auth proofs)
./target/release/prover \
    --crs-dir ./zkp-data \
    --sender alice@senderdomain.org \
    --recipient bob@receiverdomain.org

# Step 3: Run verifier (MTA-side verification)
./target/release/verifier --crs-dir ./zkp-data
```

## Running Benchmarks

### Individual circuit benchmarks

```bash
# CP_IdEnc constraint breakdown (ECDH, KDF, PRF, hash-to-prime, byte packing)
cargo test --release --features arkworks test_cpidenc_constraints -- --nocapture

# Sender auth (LegoGroth16, 7,266 constraints)
cargo test --release --features arkworks bench_auth_legogroth16 -- --nocapture

# Receiver auth (Groth16, 12,295 constraints)
cargo test --release --features arkworks bench_auth_receiver_groth16 -- --nocapture

# Full membership proof
cargo test --release --features arkworks test_membership_proof -- --nocapture
```

### Parallel scaling

```bash
# Measure proof generation across thread counts
for t in 1 2 4 6 8 10 12 14 16; do
    echo -n "Threads=$t: "
    RAYON_NUM_THREADS=$t cargo test --release --features arkworks \
        bench_auth_receiver_groth16 -- --nocapture 2>&1 | grep "Prove:"
done
```

### CP_IdEnc constraint breakdown

```bash
./target/release/prover --crs-dir ./zkp-data \
    --sender alice@senderdomain.org \
    --recipient bob@receiverdomain.org 2>&1 | grep "Step\|Total"
```

Expected output:

```
Step 1 — Hash-to-prime: 1178 constraints
Step 2 — ECDH:          5127 constraints (delta: 3949)
Step 3 — KDF:           5667 constraints (delta: 540)
Step 4 — Byte packing:  5915 constraints (delta: 248)
Step 5 — Keystream:     6455 constraints (delta: 540)
Step 6 — Encryption:    6456 constraints (delta: 1)
Total constraints:      6456
```

## Measured Performance (AWS c5.9xlarge, 36 vCPUs)

### Per-circuit benchmarks

|Circuit                 |Constraints|Setup |Prove (parallel)|Verify|Proof size|
|------------------------|-----------|------|----------------|------|----------|
|CP_IdEnc (LegoGroth16)  |6,456      |218 ms|182 ms          |43 ms |4,917 B   |
|R_auth^(S) (LegoGroth16)|7,266      |230 ms|170 ms          |7 ms  |336 B     |
|R_auth^(R) (Groth16)    |12,295     |507 ms|291 ms          |3 ms  |192 B     |

### End-to-end pipeline

|Phase                          |Time       |
|-------------------------------|-----------|
|Alice (Alg. 1 + Alg. 2 sender) |352 ms     |
|SMTP submit + relay            |186 ms     |
|Receiver MTA verify            |43 ms      |
|Bob (Alg. 2 receiver + decrypt)|321 ms     |
|**Total**                      |**~902 ms**|

### Parallel scaling (proof generation, ms)

|Threads|R_auth^(R)|R_auth^(S)|CP_IdEnc|
|-------|----------|----------|--------|
|1      |2,019     |983       |885     |
|2      |1,081     |546       |506     |
|4      |638       |339       |326     |
|8      |378       |234       |237     |
|12     |291       |202       |206     |
|16     |292       |167       |178     |

## Dependencies

|Crate                |Purpose                                            |
|---------------------|---------------------------------------------------|
|ark-bls12-381        |Pairing curve                                      |
|ark-ed-on-bls12-381  |JubJub embedded curve                              |
|ark-groth16          |Receiver-side authentication (plain Groth16)       |
|ark-crypto-primitives|Poseidon hash (H, KDF, PRF)                        |
|legogroth16          |Commit-and-prove SNARK for CP_IdEnc and sender auth|
|rug                  |GMP bindings for RSA-2048 accumulator arithmetic   |
|rayon                |Parallel MSM via Pippenger’s algorithm             |

## Acknowledgment

Built on [cpsnarks-set](https://github.com/kobigurk/cpsnarks-set)
by Kobi Gurkan, implementing protocols from “Zero-Knowledge Proofs
for Set Membership: Efficient, Succinct, Modular” (FC 2021).
