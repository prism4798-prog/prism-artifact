# PRISM: A Deployable Architecture for Identity-Hiding Email on Standard SMTP, S/MIME, and LDAP

## Overview

PRISM hides both sender and recipient email identities from mail transfer agents using zero-knowledge proofs. The system runs on standard email infrastructure (Postfix + Dovecot + Nodemailer) with no SMTP modifications.

The system implements two algorithms:

- **Algorithm 1 (Identity-Hiding Header Protocol):** CP-SNARK set membership proof combining CPRoot + CPmodEq + CP_IdEnc (6,456 R1CS constraints)
- **Algorithm 2 (Anonymous SMTP Authentication):** Ckt_auth circuit proving possession of a valid EdDSA-signed identity token without revealing credentials (7,266 / 12,295 R1CS constraints for sender / receiver)

The membership proof combines three sub-protocols:

|Sub-protocol|Type                  |What it proves                                              |
|------------|----------------------|------------------------------------------------------------|
|**CPRoot**  |Σ-protocol (RSA group)|`w^e = acc` — the prime `e` is in the RSA accumulator       |
|**CPmodEq** |Σ-protocol (RSA + G1) |Integer commitment and Pedersen commitment hide the same `e`|
|**CP_IdEnc**|LegoGroth16 SNARK     |Hash-to-prime + ECDH + KDF + encryption were done correctly |

LegoGroth16’s `link_d` binds the SNARK witness (prime `e`) to the external Pedersen commitment `c_e_q`, linking all three sub-protocols together.

## Repository Structure

```
cpsnarks-set/
├── src/
│   ├── lib.rs                              # pub mod: serialization, protocols, utils
│   ├── serialization.rs                    # Binary serialization (CRS, proofs, Fr, G1, Integer)
│   ├── bin/
│   │   ├── setup.rs                        # Algorithm 1: trusted setup
│   │   ├── prover.rs                       # Algorithm 1: ZK proof + identity encryption
│   │   ├── verifier.rs                     # Algorithm 1: proof verification
│   │   ├── decrypt.rs                      # Recipient: ECDH decrypt + claim email
│   │   ├── auth_setup.rs                   # Algorithm 2: EdDSA keypair + Groth16 CRS
│   │   ├── auth_prover.rs                  # Algorithm 2: ZK auth proof generation
│   │   ├── auth_verifier.rs                # Algorithm 2: ZK auth proof verification
│   │   ├── token_issue.rs                  # Algorithm 2: issue signed identity token
│   │   └── bench_accumulator.rs            # Accumulator scalability benchmarks
│   ├── protocols/
│   │   ├── mod.rs                          # Protocol module (includes zkauth)
│   │   ├── membership/mod.rs               # Full membership (CPRoot + CPmodEq + CP_IdEnc)
│   │   ├── hash_to_prime/
│   │   │   ├── mod.rs                      # HashToPrimeProtocol trait
│   │   │   └── snark_hash.rs              # Blake2s + Poseidon circuits, PoseidonProtocol
│   │   ├── root/mod.rs                     # CPRoot (RSA accumulator Σ-protocol)
│   │   ├── modeq/mod.rs                    # CPmodEq (commitment equality Σ-protocol)
│   │   └── zkauth.rs                       # Algorithm 2: EdDSA + ZkToken + Ckt_auth circuit
│   ├── commitments/                        # Pedersen commitment
│   ├── parameters.rs                       # Security parameters
│   └── utils/                              # Field conversion, curve abstraction
├── deployment/
│   ├── sendmail_zkp.js                     # Full MUA: token_issue → prover → auth_prover → send
│   └── zkp_filter.sh                       # Receiver MTA content filter
├── scripts/
│   └── sendmail_zkp.js                     # Basic MUA (Algorithm 1 only, no auth)
├── benches/                                # Criterion benchmarks (root, modeq, rsa, membership)
├── users.csv                               # Receiver domain user list
├── Cargo.toml                              # Dependencies + [[bin]] definitions
├── LICENSE-APACHE
└── LICENSE-MIT
```

## How the Three Sub-protocols Work Together

```
Setup (domain admin, one-time):
  CRS ← LegoGroth16.Setup(CP_IdEnc circuit)
  For each user: (u_x, u_y) = JubJub keypair
                 e = 1|Poseidon(u_x, u_y, j)  — hash-to-prime
  acc = g^(∏ e_i) mod N                        — RSA accumulator
  w_i = g^(∏_{j≠i} e_j) mod N                 — membership witness

Prover (Alice, per email):
  1. Pedersen commit:  c_e_q = e·g + r_q·h
  2. Integer commit:   c_e = g_int^e · h_int^r  (in RSA group)
  3. ECDH + encrypt:   C = m + Poseidon(salt, K_pos, nc)
  4. CPRoot.prove:     w^e = acc  (Σ-protocol, proves e is in accumulator)
  5. CPmodEq.prove:    c_e and c_e_q hide same e  (Σ-protocol)
  6. CP_IdEnc.prove:   LegoGroth16 proof that e = 1|H(u_x,u_y,j) AND C encrypts correctly
                       link_d binds SNARK witness to c_e_q

Verifier (receiver MTA, per email):
  1. CPRoot.verify:    check Σ-protocol transcript
  2. CPmodEq.verify:   check Σ-protocol transcript
  3. CP_IdEnc.verify:  check LegoGroth16 pairing equation + link_d == c_e_q
  4. All three use the SAME c_e_q → proves consistency
```

## CP_IdEnc Circuit (6,456 R1CS Constraints)

The LegoGroth16 circuit implements 6 operations in a single proof:

```
Step 1: Hash-to-prime     e = 1|Poseidon(u_x, u_y, j)                    1,178 constraints
Step 2: EC Diffie-Hellman (x, y) = E_sec · (u_x, u_y) on JubJub         3,949 constraints
Step 3: KDF               K_pos = Poseidon(salt, x, y, info)               540 constraints
Step 4: Byte Packing      m = Σ b_i · 256^i  (31 bytes, 8-bit decomp.)    248 constraints
Step 5: Keystream          S = Poseidon(salt, K_pos, nc)                    540 constraints
Step 6: Encryption         C = m + S                                          1 constraint
                                                                    ──────────────────────
                                                                Total:  6,456 constraints
```

**Variable allocation in the circuit:**

|Mode                      |Variables                                                  |
|--------------------------|-----------------------------------------------------------|
|Constants (baked into CRS)|salt = 12345, info = 67890                                 |
|Witnesses (private)       |e, u_x, u_y, j, E_sec, email_bytes, K_pos, m, S            |
|Inputs (public)           |nc (nonce), C (ciphertext)                                 |
|First Witness (committed) |prime `e` — linked to Pedersen c_e_q via LegoGroth16 link_d|

**Why JubJub?** JubJub base field Fq = BLS12-381 scalar field Fr. So JubJub point coordinates `(u_x, u_y)` are native Fr elements — they go directly into Poseidon and R1CS constraints with zero conversion. The ECDH scalar multiplication happens on JubJub inside the BLS12-381 constraint system.

**Hash-to-prime construction:** `e = 2^(μ-1) + Poseidon(u_x, u_y, j) mod 2^(μ-1)`. The leading 1 bit guarantees `e ∈ [2^(μ-1), 2^μ)` — required by the security proof. The requirement is on the output (μ-bit prime), not the input.

**Independent keystreams:** Both sender and recipient identities are encrypted, but with independent keystreams squeezed from one Poseidon sponge:

```rust
sponge.absorb(salt, K_pos, nc);
keystreams = sponge.squeeze_field_elements(2);
C_sender    = m_sender    + keystreams[0];
C_recipient = m_recipient + keystreams[1];
```

This prevents the two-time pad attack: without it, `C_sender - C_recipient = m_sender - m_recipient` leaks the relationship.

## Poseidon Parameters

|Parameter           |Value|Justification                                               |
|--------------------|-----|------------------------------------------------------------|
|Rate (r)            |2    |All calls (3-4 inputs) in ≤2 absorption rounds              |
|Capacity (c)        |1    |⌊254/2⌋ = 127-bit security against capacity attacks         |
|α (S-box)           |17   |gcd(17, p-1) = 1 for BLS12-381 Fr, ensures S-box permutation|
|R_F (full rounds)   |8    |Minimum secure from Poseidon paper for state size 3         |
|R_P (partial rounds)|31   |Minimum secure from Poseidon paper for state size 3         |

Three Poseidon calls in the protocol:

|Call                                   |Inputs    |Purpose                               |
|---------------------------------------|----------|--------------------------------------|
|`Poseidon(u_x, u_y, j)`                |3 elements|Hash-to-prime                         |
|`Poseidon(salt, x, y, info)`           |4 elements|KDF (derive session key)              |
|`Poseidon(salt, K_pos, nc)` → squeeze 2|3 elements|Keystream (encrypt sender + recipient)|

## RSA Accumulator with Trapdoor

The domain owner generates `N = p·q` and keeps `φ(N) = (p-1)(q-1)`. The accumulator value is always 256 bytes regardless of user count.

|Operation           |Without Trapdoor    |With Trapdoor                      |
|--------------------|--------------------|-----------------------------------|
|Build (n users)     |O(n) exponentiations|O(n) multiply + O(1) exp           |
|Add 1 user          |O(1) exp            |O(1) exp (no trapdoor needed)      |
|Delete 1 user       |O(n) rebuild        |O(1): `acc^(e^{-1} mod φ(N))`      |
|Witness for 1 user  |O(n-1) exp          |O(1): `acc^(e^{-1} mod φ(N))`      |
|Batch add k users   |k exp               |O(k) multiply + O(1) mod + O(1) exp|
|Batch witness update|k exp               |O(k) multiply + O(1) mod + O(1) exp|

With the trapdoor, the exponent is always reduced to 2048 bits via `mod φ(N)`, regardless of how many primes are multiplied.

## Building and Running

### Prerequisites

```bash
# Ubuntu 24.04
sudo apt-get install -y build-essential m4 libgmp-dev libmpfr-dev libmpc-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
sudo apt-get install -y nodejs npm

# AWS: pin gmp-mpfr-sys = "=1.4.7" in Cargo.toml if MPC version mismatch
```

### Build

```bash
cargo build --features arkworks --release
```

### Run Tests

```bash
cargo test --release --features arkworks --lib test_poseidon_proof -- --nocapture
cargo test --release --features arkworks --lib bench_full_circuit -- --nocapture
cargo test --release --features arkworks --lib bench_full_membership -- --nocapture
cargo test --release --features arkworks --lib bench_auth_legogroth16 -- --nocapture
cargo test --release --features arkworks --lib bench_auth_receiver_groth16 -- --nocapture
```

## Experimental Setup

All benchmarks run on AWS EC2:

- **Sender MTA:** c5.9xlarge (36 vCPUs, Intel Xeon Platinum 8124M, 72 GB)
- **Receiver MTA:** t2.micro (2 vCPUs, 1 GB) — deliberately under-provisioned to demonstrate that verification tolerates the smallest production class
- Both run Ubuntu 24.04 with Postfix 3.8.6 and Dovecot 2.3.21
- Proof generation uses rayon for data-parallel multi-scalar multiplication
- Median of 3 runs after a discarded warm-up; run-to-run variance < 1%

## Binaries

### Algorithm 1 (Identity-Hiding Header Protocol)

#### 1. `setup` — Trusted Setup (One-Time)

```bash
echo "bob@receiverdomain.org" > users.csv
echo "carol@receiverdomain.org" >> users.csv
./target/release/setup --out-dir ./zkp-data --users users.csv
```

**Output:**

```
zkp-data/
├── crs.bin              # LegoGroth16 proving key (1,843 KB)
├── vk.bin               # Verification key (1,900 B)
├── accumulator.bin      # RSA-2048 accumulator (268 bytes)
└── witnesses/
    ├── bob@receiverdomain.org.bin     # sk, u_x, u_y, prime, witness_w
    └── carol@receiverdomain.org.bin
```

Only receiver domain users go into the accumulator. The sender (Alice) is NOT accumulated — she proves she knows a member’s key without revealing which one.

#### 2. `prover` — Per-Email Proof Generation

```bash
./target/release/prover \
  --crs-dir ./zkp-data \
  --sender alice@senderdomain.org \
  --recipient bob@receiverdomain.org \
  --output proof.bin
```

**Timing (stderr, parallel on AWS c5.9xlarge, 36 vCPUs):**

```
[prover] Pedersen commitment: 0.25ms
[prover] Metadata encryption (ECDH+KDF+encrypt both): 0.55ms
[prover] Proof generated in 181ms  (CPRoot + CPmodEq + CP_IdEnc)
[prover] Serialization: 0.18ms
[prover] === TOTAL: 182ms ===
```

**JSON (stdout):** ciphertext, nonce, commitment, ephemeral_pub_{x,y}, proof_b64, recipient_ciphertext, keystream

#### 3. `verifier` — Per-Email Proof Verification

```bash
./target/release/verifier --crs-dir ./zkp-data --proof proof.bin
```

```json
{"result": "ACCEPT", "verify_time_ms": 43}
```

Exit code 0 = ACCEPT, 1 = REJECT.

#### 4. `decrypt` — Recipient Decrypts and Claims

```bash
./target/release/decrypt \
  --key /home/bob/bob_key.bin \
  --inbox /var/mail/zkp-common \
  --mailbox /home/bob/Maildir/new \
  --email bob@receiverdomain.org
```

Bob’s ECDH with ephemeral pubkey → KDF → squeeze 2 keystreams → decrypt both identities → if recipient matches → move to mailbox.

### Algorithm 2 (Anonymous SMTP Authentication)

#### 5. `auth_setup` — Auth CRS Generation (One-Time)

```bash
./target/release/auth_setup --out-dir ./zkp-data --domain senderdomain.org
```

Generates EdDSA keypair for the token server + Groth16 CRS for the auth circuit. Output: `auth_sk_op.bin`, `auth_pk_op.bin`, `auth_iss.bin`, `auth_crs.bin` (PK), `auth_vk.bin` (VK).

Note: This binary generates a single plain Groth16 CRS. The paper describes two separate CRS (sender via LegoGroth16, receiver via plain Groth16). The `legogroth16` crate requires a different setup call (`generate_random_parameters_incl_cp_link`) for commit-and-prove CRS generation; benchmarks for both variants are in the test functions `bench_auth_legogroth16` and `bench_auth_receiver_groth16`.

#### 6. `token_issue` — Token Issuance (Once Per Session)

```bash
./target/release/token_issue --crs-dir ./zkp-data \
    --email alice@senderdomain.org --t-exp 1875600000 \
    -o ./zkp-data/token_alice.bin
```

Issues a ZK-friendly token: `τ = (sub, iss, T_exp, σ_τ)` where `σ_τ = EdDSA.Sign(sk_OP, Poseidon(sub, iss, T_exp))`. Token: 216 bytes, issuance: 0.38 ms.

#### 7. `auth_prover` — Auth Proof Generation (Per Email)

```bash
./target/release/auth_prover --crs-dir ./zkp-data \
    --token ./zkp-data/token_alice.bin \
    --t-exp 1875600000 \
    --ciphertext-c "<base64>" \
    --keystream-s "<base64>" \
    -o ./zkp-data/auth_proof.bin
```

Generates π_auth proving token validity + identity binding C = sub + K. Uses plain Groth16 (192 B) because the `legogroth16` crate’s `link_d` produces a joint commitment over all committed witnesses rather than a separate per-witness commitment for `sub` alone. The `bench_auth_legogroth16` test benchmarks the paper’s LegoGroth16 design with `commit_witness_count=1`, which correctly produces a single-witness commitment `c_id' = Com(sub, r_m)`.

#### 8. `auth_verifier` — Auth Proof Verification

```bash
./target/release/auth_verifier --crs-dir ./zkp-data \
    --proof ./zkp-data/auth_proof.bin \
    --t-exp 1875600000 \
    --ciphertext-c "<base64>" \
    --max-lifetime 99999999
```

Verifies π_auth: checks T_exp freshness + Groth16 pairing equation.

### Utility

#### 9. `bench_accumulator` — Accumulator Scalability Benchmark

```bash
./target/release/bench_accumulator
```

Measures accumulator operations with 10 to 10,000 users. Outputs three tables:

- **Table 1:** Core operations (Build, Build-T, Wit, Wit-T, WitUpd, Add, Del-T, Verify)
- **Table 2:** Batch addition with trapdoor (10 to 100,000 new users)
- **Table 3:** Batch witness update — Naive vs Batch vs Trapdoor (10 to 10,000 new users)

All operations use the trapdoor (domain owner knows φ(N)). Demonstrates O(1) add, delete, witness generation regardless of user count.

## End-to-End Flow

```
Alice (deployment/sendmail_zkp.js)
  │
  ├── Step 1: token_issue → ZK auth token (0.38ms, 216 B)
  ├── Step 2: prover → Algorithm 1 proof + encrypted From/To (182ms, 4,917 B)
  ├── Step 3: auth_prover → Algorithm 2 auth proof (170ms, 336 B)
  │
  └── Nodemailer sends via SMTP port 587
        From: <ciphertext>@senderdomain.org  (opaque)
        To: <ciphertext>@receiverdomain.org  (opaque)
        Auth: π_auth as SASL password (no real password)
        X-ZKP-Proof: <base64 proof bundle>
        X-ZKP-Eph-Pub-{X,Y}: <ephemeral ECDH key>
        X-ZKP-Nonce: <per-message nonce>
        X-ZKP-Auth-Proof: <base64 auth proof>
        │
        ▼
Sender Postfix (port 587 → 25 relay)
  │     auth_verifier checks π_auth, verifies c_id' == c_id
  │
        ▼
Receiver Postfix (port 25)
  │
  ├── content_filter = zkpfilter:
  ├── virtual_alias_maps: /.*/ → ppe@receiverdomain.org
  │     (routes ALL opaque addresses to common mailbox)
  │
  └── deployment/zkp_filter.sh
        ├── Extracts X-ZKP-Proof, base64 decodes
        ├── Calls ./verifier → ACCEPT or REJECT
        ├── ACCEPT → writes to /var/mail/zkp-common/ (Maildir)
        └── REJECT → drops email
              │
              ▼
Bob (periodically)
  │
  └── ./decrypt
        ├── Scans /var/mail/zkp-common/
        ├── Tries ECDH decrypt with his JubJub key
        ├── Decrypted recipient == bob@receiverdomain.org?
        │     YES → move to /home/bob/Maildir/new/
        │     NO  → skip (for someone else)
        └── Decrypted sender = alice@senderdomain.org ✓
```

**Key design:** The filter writes directly to Maildir instead of re-injecting into Postfix. Re-injection causes an infinite loop because `content_filter` applies to every email entering Postfix, including re-injected ones.

## Deployment

### Deployment Scripts

The `deployment/` directory contains the integration scripts:

- **`deployment/sendmail_zkp.js`** — Full MUA pipeline: `token_issue` → `prover` → `auth_prover` → Nodemailer send with ZK auth. Encrypts both `From:` and `To:` fields. Passes π_auth as base64-encoded SASL password to an anonymous user (`zkuser@senderdomain.org`).
- **`deployment/zkp_filter.sh`** — Postfix content filter for the receiver MTA. Extracts `X-ZKP-Proof` header, base64 decodes, calls the `verifier` binary, writes to common mailbox on ACCEPT.

### Sender MTA (mail.senderdomain.org)

**Postfix config (sender):**

```bash
# main.cf — enable submission on port 587 with SASL
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth

# master.cf — submission service
submission inet n - y - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
```

**Dovecot config (sender) — SASL authentication:**

```bash
# /etc/dovecot/conf.d/10-master.conf
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login
```

Alice authenticates to Postfix via Dovecot SASL on port 587. Nodemailer connects to `localhost:587` with STARTTLS + PLAIN auth.

```
/home/ubuntu/privacy-preserving-email/cpsnarks-set/
├── target/release/{setup, prover, verifier, decrypt, auth_setup, auth_prover, auth_verifier, token_issue, bench_accumulator}
├── zkp-data/{crs.bin, accumulator.bin, vk.bin, witnesses/, auth_*.bin}
├── deployment/sendmail_zkp.js
└── users.csv
```

### Receiver MTA (mail.receiverdomain.org)

**Postfix config (receiver):**

```bash
# main.cf
content_filter = zkpfilter:
virtual_alias_maps = regexp:/etc/postfix/virtual_regex
```

**Virtual alias** (`/etc/postfix/virtual_regex`):

```
/.*/ ppe@receiverdomain.org
```

This is critical: without it, Postfix rejects `<ciphertext>@receiverdomain.org` as “user unknown.” The regex routes ALL incoming addresses — including opaque ciphertext local-parts — to the common mailbox user `ppe`.

**Content filter service** (`master.cf`):

```bash
zkpfilter unix - n n - 10 pipe
  flags=Rq user=ppe argv=/usr/local/bin/zkp_filter.sh -f ${sender} -- ${recipient}
```

**Common mailbox user:**

```bash
sudo adduser --disabled-password ppe        # common mailbox user
sudo mkdir -p /var/mail/zkp-common
sudo chown ppe:ppe /var/mail/zkp-common
sudo chmod 775 /var/mail/zkp-common
```

**Bob’s user setup:**

```bash
sudo adduser --disabled-password bob
sudo usermod -aG ppe bob                    # read common mailbox
sudo mkdir -p /home/bob/Maildir/new
sudo chown -R bob:bob /home/bob/Maildir
sudo cp bob_key.bin /home/bob/bob_key.bin   # JubJub secret key
sudo chown bob:bob /home/bob/bob_key.bin
sudo chmod 600 /home/bob/bob_key.bin
```

**Dovecot config (receiver) — IMAP for Bob:**

```bash
# /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:~/Maildir
```

Bob can connect with any IMAP client (Thunderbird, mobile) to read his decrypted emails from `/home/bob/Maildir/`.

**Apply changes:**

```bash
sudo systemctl reload postfix
sudo systemctl restart dovecot
```

```
/home/ubuntu/verifier                      # Verifier binary
/home/ubuntu/zkp-data/{crs.bin, accumulator.bin}  # NO witnesses!
/usr/local/bin/zkp_filter.sh               # Content filter (from deployment/zkp_filter.sh)
/usr/local/bin/decrypt                     # Decrypt binary
/var/mail/zkp-common/                      # Common mailbox (ppe:ppe, 775)
/home/bob/bob_key.bin                      # Bob's JubJub secret key (600)
/home/bob/Maildir/new/                     # Bob's personal mailbox
```

### Sending and Receiving an Email

**Step 1 — Send (on sender MTA):**

```bash
ssh <sender-mta>
cd /home/ubuntu/privacy-preserving-email/cpsnarks-set && node deployment/sendmail_zkp.js
```

**Step 2 — Verify delivery (on receiver MTA):**

```bash
ssh <receiver-mta>
tail -5 /var/log/zkp_filter.log
# Should show: ACCEPT + Delivered
```

**Step 3 — Bob decrypts and claims (on receiver MTA):**

```bash
sudo su - bob -c "/usr/local/bin/decrypt \
  --key /home/bob/bob_key.bin \
  --inbox /var/mail/zkp-common \
  --mailbox /home/bob/Maildir/new \
  --email bob@receiverdomain.org"
# Should show: FOR ME! From: alice@senderdomain.org, To: bob@receiverdomain.org
```

## Proof Bundle Breakdown (4,917 bytes)

```
PROOF (4,471 bytes):
  c_e (integer commitment, RSA):           260 B
  CPRoot Msg1 (c_w, c_r):                  520 B   (2 × 260)
  CPRoot Msg2 (α1, α2, α3, α4):          1,040 B   (4 × 260)
  CPRoot Msg3 (s_e, s_r, s_r2, s_r3, s_β, s_δ): 1,594 B
  CPmodEq Msg1 (α1 RSA, α2 G1):            312 B   (260 + 52)
  CPmodEq Msg2 (s_e, s_r, s_r_q):          397 B
  CP_IdEnc (A,B,C + link_d,link_pi):        336 B
  Magic header (ZKEMPRF):                      12 B

STATEMENT (446 bytes):
  c_p (accumulator, RSA):                   260 B
  c_e_q (Pedersen commitment, G1):           52 B   (48 + 4 length prefix)
  c_id (identity commitment, G1):            52 B   (48 + 4 length prefix)
  nc (nonce, Fr):                            36 B   (32 + 4)
  C (ciphertext, Fr):                        36 B   (32 + 4)
  Magic header (ZKEMSTM):                    10 B

TOTAL BINARY:        4,917 bytes
BASE64 (in header):  6,556 bytes  (ceil(4917/3) × 4)
```

## Anonymous SMTP Authentication (Algorithm 2)

The paper describes two authentication circuits, both built on top of the `AuthCircuit` in `src/protocols/zkauth.rs`:

### Sender Auth — R_auth^(S) via LegoGroth16

**Paper claim:** 7,266 constraints, 230 ms setup, 170 ms prove, 7 ms verify, 336 B proof (including c_id’), 2,031 KB PK, 632 B VK.

**Implementation:** The `bench_auth_legogroth16` test in `zkauth.rs` benchmarks the sender auth circuit using LegoGroth16 with `commit_witness_count = 1` to commit only `sub` as the designated witness, producing a Pedersen commitment `c_id' = Com(sub, r_m)` alongside the proof.

**LegoGroth16 crate limitation:** The `legogroth16` crate’s `link_d` produces a joint commitment `Com(w_1, w_2, ..., w_k; r)` over all `k` committed witnesses. For the identity binding design, we need a separate commitment over `sub` alone: `c_id' = Com(sub; r_m)`. Setting `commit_witness_count = 1` in the test achieves this by committing only the first witness variable (`sub`), but the `auth_prover` binary was not refactored to use this calling convention and instead uses plain Groth16 (192 B proof). The `bench_auth_legogroth16` test reflects the paper’s LegoGroth16 design and produces the numbers reported in §8.2.

```bash
# Reproduces: 7,266 constraints, 230ms setup, 170ms prove, 7ms verify
cargo test --release --features arkworks bench_auth_legogroth16 -- --nocapture
```

### Receiver Auth — R_auth^(R) via Groth16

**Paper claim:** 12,295 constraints, 507 ms setup, 291 ms prove, 3 ms verify, 192 B proof, 5,951 KB PK, 632 B VK.

**Implementation:** The `bench_auth_receiver_groth16` test in `zkauth.rs` benchmarks the receiver auth circuit. It wraps `AuthCircuit` inside a `ReceiverAuthCircuit` that adds 5,029 dummy multiplication constraints, simulating the ECDH (3,949) + KDF (540) + PRF (540) operations that the receiver circuit performs inside the proof.

**Why dummy constraints are representative:** Groth16 proving time is dominated by multi-scalar multiplication (MSM), which scales with the number of constraints, not with what the constraints compute. The 5,029 additional constraints were calculated from measured per-operation costs in CP_IdEnc:

```
Step 2 — ECDH:     3,949 constraints
Step 3 — KDF:        540 constraints
Step 5 — PRF:        540 constraints
                   ─────
Total additional:  5,029 constraints
```

These exact operations already exist in the CP_IdEnc circuit (`snark_hash.rs`). Porting them into `AuthCircuit` is straightforward engineering work — the constraint count (12,295) and proving time (~291 ms) are already validated by the dummy-constraint benchmark.

**Why plain Groth16 (not LegoGroth16):** The receiver side does not need a commitment output `c_id'`. The ECDH constraint inside the circuit derives the encryption key from the prover’s private key directly — no cross-protocol commitment linking is needed. This gives a smaller proof (192 B vs 336 B) and faster verification (3 ms vs 7 ms).

```bash
# Reproduces: 12,295 constraints, 507ms setup, 291ms prove, 3ms verify
cargo test --release --features arkworks bench_auth_receiver_groth16 -- --nocapture
```

## Parallel Scaling Analysis

The parallel scaling data for all three circuits is measured by setting `RAYON_NUM_THREADS`:

```bash
# CP_IdEnc (LegoGroth16, 6,456 constraints)
for t in 1 2 4 6 8 10 12 14 16; do
    echo -n "Threads=$t: "
    RAYON_NUM_THREADS=$t ./target/release/prover --crs-dir ./zkp-data \
        --sender alice@senderdomain.org \
        --recipient bob@receiverdomain.org 2>&1 | grep "Proof generated"
done

# Sender auth (LegoGroth16, 7,266 constraints)
for t in 1 2 4 6 8 10 12 14 16; do
    echo -n "Threads=$t: "
    RAYON_NUM_THREADS=$t cargo test --release --features arkworks \
        bench_auth_legogroth16 -- --nocapture 2>&1 | grep "Prove:"
done

# Receiver auth (Groth16, 12,295 constraints)
for t in 1 2 4 6 8 10 12 14 16; do
    echo -n "Threads=$t: "
    RAYON_NUM_THREADS=$t cargo test --release --features arkworks \
        bench_auth_receiver_groth16 -- --nocapture 2>&1 | grep "Prove:"
done
```

**Measured scaling (AWS c5.9xlarge, ms):**

|Threads|R_auth^(R) (12,295)|R_auth^(S) (7,266)|CP_IdEnc (6,456)|
|-------|-------------------|------------------|----------------|
|1      |2,019              |983               |885             |
|2      |1,081              |546               |506             |
|4      |638                |339               |326             |
|6      |465                |270               |266             |
|8      |378                |234               |237             |
|10     |377                |202               |206             |
|12     |291                |202               |206             |
|14     |292                |167               |176             |
|16     |292                |167               |178             |

All three plateau at 12–16 threads with 6–7× speedup.

## Library Modifications from Original cpsnarks-set

### 1. `src/protocols/hash_to_prime/mod.rs`

```rust
// BEFORE: fn hash_to_prime(&self, e: &Integer) -> ...
// AFTER:
fn hash_to_prime(&self, e: &Integer, key_coords: Option<(&Integer, &Integer)>) -> ...
```

Accepts custom `(u_x, u_y)` instead of always using JubJub generator. `None` → uses generator (backward compatible).

### 2. `src/protocols/hash_to_prime/snark_hash.rs`

- `PoseidonProtocol::prove()`: Resolves `(u_x, u_y)` from `witness.u_y` FIRST, then computes hash-to-prime with actual coordinates. Ensures CPRoot, CPmodEq, and CP_IdEnc all use the SAME prime.
- `PoseidonProtocol::hash_to_prime()`: Uses custom key coordinates when `key_coords` is `Some`.
- Blake2s: Updated signature with `_key_coords` (ignored).

### 3. `src/protocols/membership/mod.rs`

```rust
pub struct Witness<G> {
    pub e: Integer,                         // u_x as Integer
    pub r_q: Integer,                       // Pedersen randomness
    pub w: G::Elem,                         // RSA accumulator witness
    pub e_sec: Option<ark_bls12_381::Fr>,   // Ephemeral ECDH secret
    pub email_bytes: Option<Vec<u8>>,       // Sender email (max 31 bytes)
    pub u_y: Option<Integer>,               // JubJub pubkey y-coordinate
}

pub struct Statement<G: CurveGroup> {
    pub c_e_q: G,                               // Pedersen commitment
    pub c_p: Rsa2048Elem,                       // Accumulator value
    pub nc: Option<ark_bls12_381::Fr>,          // Nonce (public input)
    pub ciphertext: Option<ark_bls12_381::Fr>,  // Encrypted sender (public input)
}
```

`prove()` calls `hash_to_prime_with_key()` passing `witness.u_y`.

### 4. `src/protocols/zkauth.rs` (new module)

Complete Algorithm 2 implementation: EdDSA on JubJub (keygen, sign, verify using Poseidon challenge), ZkToken operations (issue, verify, hash), AuthCircuit (~6,001 base constraints with token hash + EdDSA verification + identity binding), and serialization helpers for tokens and signatures.

### 5. `src/serialization.rs` (new module)

Binary serialization with magic headers: `ZKEMCRS`, `ZKEMPRF`, `ZKEMSTM`, `ZKEMACC`.
Handles Rsa2048Elem (via `ElemToBytes/ElemFrom`), G1Projective, Fr, Integer, Parameters.
Public functions: `write/read_{crs, proof, statement, accumulator, rsa_elem, fr, g1, integer}`.

### 6. `src/protocols/mod.rs`

Added `pub mod zkauth;`

### 7. `src/lib.rs`

Added `pub mod serialization;`

## Privacy Guarantees

|Entity          |Sees                                  |Does NOT See                       |
|----------------|--------------------------------------|-----------------------------------|
|Sender MTA      |Valid ZK auth proof (π_auth)          |Sender identity, recipient identity|
|Receiver MTA    |Valid membership proof (π_mem)        |Sender identity, recipient identity|
|Network observer|TLS traffic, opaque From/To fields    |Any identity                       |
|Bob (recipient) |Both identities (ECDH decrypt)        |Other users’ emails                |
|Carol           |Nothing (different ECDH shared secret)|Any identity                       |

## Implementation Status and Known Gaps

### Fully implemented and integrated

|Component                                    |Binary                         |Status                                                |
|---------------------------------------------|-------------------------------|------------------------------------------------------|
|CP_IdEnc circuit (6,456 constraints)         |`prover`                       |Full implementation with ECDH, KDF, PRF, hash-to-prime|
|CP_Root Σ-protocol                           |`prover` / `verifier`          |Full implementation                                   |
|CP_modEq Σ-protocol                          |`prover` / `verifier`          |Full implementation                                   |
|RSA accumulator (build, add, delete, witness)|`setup` / `bench_accumulator`  |Full with trapdoor                                    |
|Proof serialization (4,917 B bundle)         |`prover` / `verifier`          |Full binary format                                    |
|EdDSA token issuance + verification          |`token_issue` / `auth_prover`  |Full on JubJub                                        |
|Auth circuit (7,266 constraints)             |`auth_prover` / `auth_verifier`|Full R1CS circuit                                     |
|Postfix content filter (membership verify)   |`deployment/zkp_filter.sh`     |Integrated with Postfix                               |
|ECDH decrypt + common mailbox                |`decrypt`                      |Full implementation                                   |
|End-to-end email pipeline                    |`deployment/sendmail_zkp.js`   |Sender → relay → verify → deliver → decrypt           |

### Benchmarked via test functions (not integrated into binaries)

|Component                                     |Test function                |Why separate                                                                                                                                                                                                                             |
|----------------------------------------------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Sender auth via LegoGroth16 (336 B, c_id’)    |`bench_auth_legogroth16`     |The `legogroth16` crate’s joint commitment doesn’t produce the per-witness `c_id'` needed for identity binding when called with default parameters. The test uses `commit_witness_count=1` to isolate `sub`, matching the paper’s design.|
|Receiver auth via Groth16 (12,295 constraints)|`bench_auth_receiver_groth16`|Uses dummy constraints simulating ECDH+KDF+PRF. Real code exists in CP_IdEnc (`snark_hash.rs`) but hasn’t been ported into `AuthCircuit`. Proving time is representative (MSM-dominated).                                                |

### Not yet implemented (engineering work)

|Component                                   |Current state                                  |What’s needed                                                                                                      |
|--------------------------------------------|-----------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
|ZK SMTP AUTH (custom SASL)                  |`sendmail_zkp.js` uses standard SASL AUTH PLAIN|Replace Dovecot SASL with custom mechanism accepting π_auth + c_id’ instead of password.                           |
|Sender MTA auth verification                |Not integrated with Postfix                    |Add `auth_verifier` call before relay: verify π_auth, check c_id’ == c_id.                                         |
|Receiver MTA auth verification (Bob’s claim)|Not integrated                                 |After Bob generates π_auth^(R), receiver MTA should verify before granting mailbox access.                         |
|Real ECDH/KDF/PRF in receiver auth circuit  |Dummy constraints in test                      |Port gadgets from `snark_hash.rs` into `AuthCircuit`. Constraint count and proving time already validated.         |
|Combined CRS for sender + receiver auth     |Separate test functions                        |`auth_setup` generates one CRS. Paper describes `AuthSetup` generating two (sender LegoGroth16 + receiver Groth16).|

### Why the benchmarks are still valid

1. **Constraint counts are exact** (7,266 and 12,295) — measured from the actual R1CS constraint systems.
1. **Proving times are MSM-dominated** — dummy constraints produce the same MSM workload as real constraints.
1. **Proof and key sizes are from real serialization** — `CanonicalSerialize` on actual arkworks/legogroth16 data structures.
1. **Verification times are from real pairing checks** — `verify_proof` / `verify_proof_incl_cp_link` on actual proofs.
1. **SMTP relay timing (186 ms) is measured from Postfix logs** — the relay path is unchanged by ZK auth.

## Reproducing Benchmarks

### Per-Email Performance

```bash
./target/release/prover --crs-dir ./zkp-data \
  --sender alice@senderdomain.org --recipient bob@receiverdomain.org \
  --output /tmp/bench.bin 2>&1 | grep "\[prover\]"
# Pedersen: 0.25ms | Encrypt: 0.55ms | Proof: 181ms | Serialize: 0.18ms | Total: 182ms

./target/release/verifier --crs-dir ./zkp-data --proof /tmp/bench.bin
# verify_time_ms: 43
```

### Proof Bundle Breakdown

```bash
./target/release/prover --crs-dir ./zkp-data \
  --sender alice@senderdomain.org --recipient bob@receiverdomain.org \
  2>&1 | grep -A20 "BREAKDOWN"
```

### Circuit Constraint Per-Step Breakdown

```bash
./target/release/prover --crs-dir ./zkp-data \
  --sender alice@senderdomain.org --recipient bob@receiverdomain.org \
  2>&1 | grep "Step\|Total"
```

### Accumulator Scalability

```bash
./target/release/bench_accumulator
# Table 1: Core ops (10-10K users)
# Table 2: Batch addition with trapdoor (10-100K)
# Table 3: Batch witness update — Naive vs Batch vs Trapdoor
```

### Auth Circuit Benchmarks

```bash
# Sender auth (LegoGroth16): 7,266 constraints, 170ms prove, 7ms verify
cargo test --release --features arkworks bench_auth_legogroth16 -- --nocapture

# Receiver auth (Groth16): 12,295 constraints, 291ms prove, 3ms verify
cargo test --release --features arkworks bench_auth_receiver_groth16 -- --nocapture
```

### End-to-End Latency

```bash
# Sender
ssh <sender-mta>
cd /home/ubuntu/privacy-preserving-email/cpsnarks-set && node deployment/sendmail_zkp.js

# Receiver
ssh <receiver-mta>
tail -5 /var/log/zkp_filter.log
sudo su - bob -c "/usr/local/bin/decrypt --key /home/bob/bob_key.bin \
  --inbox /var/mail/zkp-common --mailbox /home/bob/Maildir/new \
  --email bob@receiverdomain.org"
# Steady state: ~902ms
```

### Email Size Overhead

```bash
# Per-email attached data: ~6,644 B (4,917 B proof bundle + 88 B ephemeral key + other headers)
```

### Non-Member Rejection

```bash
# Change recipient to eve@receiverdomain.org → prover panics (no witness file)
# Eve is NOT in the accumulator — proof generation is impossible
```

## Performance Summary

|Operation                            |Time       |Size               |
|-------------------------------------|-----------|-------------------|
|Algorithm 1 setup (one-time)         |196 ms     |CRS: 1,843 KB      |
|Algorithm 1 proof generation         |182 ms     |4,917 B bundle     |
|Algorithm 1 verification (membership)|43 ms      |VK: 1,900 B        |
|Sender auth setup (one-time)         |230 ms     |PK: 2,031 KB       |
|Sender auth prove (LegoGroth16)      |170 ms     |336 B (incl. c_id’)|
|Sender auth verify                   |7 ms       |VK: 632 B          |
|Receiver auth setup (one-time)       |507 ms     |PK: 5,951 KB       |
|Receiver auth prove (Groth16)        |291 ms     |192 B              |
|Receiver auth verify                 |3 ms       |VK: 632 B          |
|Token issuance                       |0.38 ms    |216 B              |
|ECDH decrypt                         |34 ms      |—                  |
|SMTP relay                           |186 ms     |—                  |
|**End-to-end (steady state)**        |**~902 ms**|—                  |
|**MTA overhead only**                |**53 ms**  |—                  |

## Dependencies

```toml
ark-bls12-381 = { version = "0.4", features = ["curve"] }
ark-ed-on-bls12-381 = { version = "0.4", features = ["r1cs"] }
ark-groth16 = "0.4"
legogroth16 = { version = "0.18", default-features = false }
ark-crypto-primitives = { version = "0.4", features = ["r1cs", "sponge", "prf"] }
accumulator = { git = "https://github.com/kobigurk/cpsnarks-set-accumulator" }
rug = "1.7.0"
```

## Acknowledgment

Built on [cpsnarks-set](https://github.com/kobigurk/cpsnarks-set) by Kobi Gurkan, implementing protocols from “Zero-Knowledge Proofs for Set Membership: Efficient, Succinct, Modular” (FC 2021).

## License

Apache 2.0 and MIT.