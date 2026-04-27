#!/usr/bin/env node
/**
 * sendmail_zkp.js — Privacy-Preserving Email Sender
 *
 * Calls the Rust prover binary to generate a ZK membership proof,
 * then sends the email via Nodemailer with proof data in custom headers.
 *
 * The From: field is replaced with the ciphertext C (encrypted sender identity).
 * Only the intended recipient can decrypt C to learn who sent the email.
 *
 * Usage:
 *   node sendmail_zkp.js \
 *     --to bob@receiverdomain.org \
 *     --subject "Hello" \
 *     --body "This is a private email"
 *
 * Prerequisites:
 *   - cargo build --bin prover --features arkworks --release
 *   - setup has been run: ./zkp-data/ contains crs.bin, accumulator.bin, witnesses/
 *   - npm install nodemailer
 */

const { execSync } = require('child_process');
const nodemailer = require('nodemailer');
const path = require('path');

// ============================================================
// Configuration — adjust for your deployment
// ============================================================
const CONFIG = {
    // SMTP server (sender MTA)
    smtp: {
        host: 'mail.senderdomain.org',
        port: 587,
        secure: false, // STARTTLS
        auth: {
            user: 'alice@senderdomain.org',
            pass: 'alice',
            // For OAuth2:
            // type: 'OAuth2',
            // accessToken: process.env.OAUTH_TOKEN,
        },
        tls: { rejectUnauthorized: false }, // for self-signed certs in dev
    },
    // Sender identity
    sender: 'alice@senderdomain.org',
    // Path to compiled prover binary
    proverBin: path.join(__dirname, '..', 'target', 'release', 'prover'),
    // Path to ZKP data directory (output of setup)
    crsDir: path.join(__dirname, '..', 'zkp-data'),
    // CA identifier
    caId: 'senderdomain.org',
};

// ============================================================
// Parse CLI arguments
// ============================================================
const args = process.argv.slice(2);
let recipient = 'bob@receiverdomain.org';
let subject = 'ZKP Private Email';
let body = 'This is a privacy-preserving email.';

for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '--to': recipient = args[++i]; break;
        case '--subject': subject = args[++i]; break;
        case '--body': body = args[++i]; break;
        case '--help':
            console.log('Usage: node sendmail_zkp.js [--to EMAIL] [--subject STR] [--body STR]');
            process.exit(0);
    }
}

async function main() {
    console.log(`[sendmail] Generating ZK proof for ${CONFIG.sender} → ${recipient}...`);

    // ============================================================
    // Step 1: Call Rust prover binary
    // ============================================================
    const proverCmd = [
        CONFIG.proverBin,
        '--crs-dir', CONFIG.crsDir,
        '--sender', CONFIG.sender,
        '--recipient', recipient,
        '--ca', CONFIG.caId,
    ].join(' ');

    let proofJson;
    try {
        const stdout = execSync(proverCmd, {
            encoding: 'utf-8',
            timeout: 60000, // 60s timeout for proof generation
            // stderr goes to parent process stderr (shows progress)
        });
        proofJson = JSON.parse(stdout);
    } catch (err) {
        console.error('[sendmail] ERROR: Prover failed:', err.message);
        if (err.stderr) console.error(err.stderr.toString());
        process.exit(1);
    }

    console.log(`[sendmail] Proof generated in ${proofJson.prove_time_ms}ms (${proofJson.proof_size_bytes} bytes)`);

    // ============================================================
    // Step 2: Construct the opaque From address
    // The ciphertext C replaces the sender identity in the From: field
    // ============================================================
    const opaqueFrom = `${proofJson.ciphertext.substring(0, 40)}@${CONFIG.caId}`;

    // ============================================================
    // Step 3: Send email via Nodemailer with proof headers
    // ============================================================
    const transporter = nodemailer.createTransport(CONFIG.smtp);

    const mailOptions = {
        from: opaqueFrom,
        to: recipient,
        subject: subject,
        text: body,
        headers: {
            // ZK proof data — verifier uses these
            'X-ZKP-Proof': proofJson.proof_b64,
            'X-ZKP-Ciphertext': proofJson.ciphertext,
            'X-ZKP-Nonce': proofJson.nonce,
            'X-ZKP-Commitment': proofJson.commitment,
            'X-ZKP-Eph-Pub-X': proofJson.ephemeral_pub_x,
            'X-ZKP-Eph-Pub-Y': proofJson.ephemeral_pub_y,
            'X-ZKP-CA': proofJson.ca_id,
        },
    };

    console.log(`[sendmail] Sending email...`);
    console.log(`  From: ${opaqueFrom} (encrypted)`);
    console.log(`  To: ${recipient}`);
    console.log(`  Subject: ${subject}`);

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log(`[sendmail] Message sent: ${info.messageId}`);
        console.log(`[sendmail] Response: ${info.response}`);
    } catch (err) {
        console.error('[sendmail] SMTP ERROR:', err.message);
        process.exit(1);
    }
}

main().catch(err => {
    console.error('[sendmail] Fatal:', err);
    process.exit(1);
});
