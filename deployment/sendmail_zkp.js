const nodemailer = require("nodemailer");
const { execSync } = require("child_process");
const fs = require("fs");

const PROVER_BIN = "/home/ubuntu/privacy-preserving-email/cpsnarks-set/target/release/prover";
const TOKEN_ISSUE_BIN = "/home/ubuntu/privacy-preserving-email/cpsnarks-set/target/release/token_issue";
const AUTH_PROVER_BIN = "/home/ubuntu/privacy-preserving-email/cpsnarks-set/target/release/auth_prover";
const CRS_DIR = "/home/ubuntu/privacy-preserving-email/cpsnarks-set/zkp-data";
const TOKEN_FILE = "/tmp/zkp_token.bin";
const AUTH_PROOF_FILE = "/tmp/zkp_auth_proof.bin";

async function main() {
  const sender = "alice@senderdomain.org";
  const recipient = "bob@receiverdomain.org";
  const subject = "ZKP Private Email Test";
  const body = "This is a privacy-preserving email. Sender identity is encrypted.";

  // ============================================================
  // Step 1: Issue ZK token (simulates Keycloak token server)
  // ============================================================
  console.log("[zkp-mail] Step 1: Issuing ZK token...");
  const t_exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

  const tokenCmd = [
    TOKEN_ISSUE_BIN,
    "--crs-dir", CRS_DIR,
    "--email", sender,
    "--t-exp", t_exp.toString(),
    "-o", TOKEN_FILE
  ].join(" ");

  try {
    execSync(tokenCmd, { encoding: "utf-8", timeout: 10000 });
  } catch (err) {
    console.error("[zkp-mail] Token issue failed:", err.message);
    if (err.stderr) console.error(err.stderr.toString());
    process.exit(1);
  }
  console.log("[zkp-mail] Token issued (t_exp=" + t_exp + ")");

  // ============================================================
  // Step 2: Generate Algorithm 2 proof (membership + encryption)
  // ============================================================
  console.log("[zkp-mail] Step 2: Generating Algorithm 2 proof...");
  const proverCmd = [
    PROVER_BIN,
    "--crs-dir", CRS_DIR,
    "--sender", sender,
    "--recipient", recipient,
    "--ca", "senderdomain.org"
  ].join(" ");

  let proof;
  try {
    const stdout = execSync(proverCmd, { encoding: "utf-8", timeout: 120000 });
    const jsonStart = stdout.indexOf("{");
    const jsonEnd = stdout.lastIndexOf("}");
    proof = JSON.parse(stdout.substring(jsonStart, jsonEnd + 1));
  } catch (err) {
    console.error("[zkp-mail] Prover failed:", err.message);
    if (err.stderr) console.error(err.stderr.toString());
    process.exit(1);
  }
  console.log("[zkp-mail] Algorithm 2 proof generated in " + proof.prove_time_ms + "ms (" + proof.proof_size_bytes + " bytes)");

  // ============================================================
  // Step 3: Generate Algorithm 3 proof (anonymous authentication)
  //   Uses C (ciphertext) and S (keystream) from Algorithm 2
  //   Identity binding: C = sub + K where K = S
  // ============================================================
  console.log("[zkp-mail] Step 3: Generating Algorithm 3 proof...");
  const authProverCmd = [
    AUTH_PROVER_BIN,
    "--crs-dir", CRS_DIR,
    "--token", TOKEN_FILE,
    "--t-exp", t_exp.toString(),
    "--ciphertext-c", proof.ciphertext,
    "--keystream-s", proof.keystream,
    "-o", AUTH_PROOF_FILE
  ].join(" ");

  let authProof;
  try {
    const stdout = execSync(authProverCmd, { encoding: "utf-8", timeout: 120000 });
    const jsonStart = stdout.indexOf("{");
    const jsonEnd = stdout.lastIndexOf("}");
    authProof = JSON.parse(stdout.substring(jsonStart, jsonEnd + 1));
  } catch (err) {
    console.error("[zkp-mail] Auth prover failed:", err.message);
    if (err.stderr) console.error(err.stderr.toString());
    process.exit(1);
  }
  console.log("[zkp-mail] Algorithm 3 proof generated in " + authProof.prove_time_ms + "ms (" + authProof.proof_size_bytes + " bytes)");

  // ============================================================
  // Step 4: Build SASL credential (π_auth bundle)
  //   Instead of username/password, we send the ZK proof
  //   The ZK Auth Proxy on the MTA verifies this
  // ============================================================
  const authBundle = JSON.stringify({
    auth_proof_b64: authProof.auth_proof_b64,
    t_exp: t_exp.toString(),
    ciphertext_c: proof.ciphertext
  });

  // Encode as base64 for SASL password field
  const authPassword = Buffer.from(authBundle).toString("base64");

  // ============================================================
  // Step 5: Submit email via SMTP with ZK authentication
  // ============================================================
  console.log("[zkp-mail] Step 4: Submitting email with ZK auth...");
  const opaqueFrom = proof.ciphertext.replace(/[+/=]/g, "").substring(0, 40) + "@senderdomain.org";
  const opaqueTo = proof.recipient_ciphertext.replace(/[+/=]/g, "").substring(0, 40) + "@receiverdomain.org";
  console.log("[zkp-mail] Opaque From: " + opaqueFrom);

  const transporter = nodemailer.createTransport({
    host: "127.0.0.1",
    port: 587,
    secure: false,
    auth: {
      user: "zkuser@senderdomain.org",   // anonymous user — MTA doesn't learn identity
      pass: authPassword,                 // π_auth bundle, verified by ZK Auth Proxy
    },
    tls: { rejectUnauthorized: false },
  });

  const info = await transporter.sendMail({
    from: opaqueFrom,
    to: opaqueTo,
    subject: subject,
    text: body,
    headers: {
      "X-ZKP-Proof": proof.proof_b64,
      "X-ZKP-Ciphertext": proof.ciphertext,
      "X-ZKP-Recipient-Ciphertext": proof.recipient_ciphertext,
      "X-ZKP-Nonce": proof.nonce,
      "X-ZKP-Commitment": proof.commitment,
      "X-ZKP-Eph-Pub-X": proof.ephemeral_pub_x,
      "X-ZKP-Eph-Pub-Y": proof.ephemeral_pub_y,
      "X-ZKP-CA": proof.ca_id,
      "X-ZKP-Auth-Proof": authProof.auth_proof_b64,
      "X-ZKP-Auth-T-Exp": t_exp.toString(),
    },
  });

  console.log("[zkp-mail] Message sent: " + info.messageId);
  console.log("[zkp-mail] From: " + opaqueFrom + " (encrypted identity)");
  console.log("[zkp-mail] To: " + recipient);
  console.log("[zkp-mail] Auth: ZK proof (no password revealed to MTA)");

  // Cleanup temp files
  try { fs.unlinkSync(TOKEN_FILE); } catch (e) {}
  try { fs.unlinkSync(AUTH_PROOF_FILE); } catch (e) {}
}

main().catch(function(err) {
  console.error("[zkp-mail] Send failed:", err);
  process.exit(1);
});