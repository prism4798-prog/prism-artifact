#!/bin/bash
VERIFIER="/home/ubuntu/verifier"
CRS_DIR="/home/ubuntu/zkp-data"
MAILDIR="/var/mail/zkp-common"
TMPFILE=$(mktemp /tmp/zkp_mail.XXXXXX)
cat > "$TMPFILE"
PROOF_B64=$(sed -n '/^X-Zkp-Proof:/,/^[^ \t]/{p}' "$TMPFILE" | tail -n +2 | grep '^ ' | tr -d ' \n\r')
if [ -n "$PROOF_B64" ]; then
    PROOF_BIN=$(mktemp /tmp/zkp_proof.XXXXXX)
    echo "$PROOF_B64" | base64 -d > "$PROOF_BIN" 2>/dev/null
    $VERIFIER --crs-dir "$CRS_DIR" --proof "$PROOF_BIN" 2>/dev/null
    EXIT_CODE=$?
    rm -f "$PROOF_BIN"
    if [ $EXIT_CODE -ne 0 ]; then
        echo "$(date): REJECT" >> /var/log/zkp_filter.log
        rm -f "$TMPFILE"
        exit 0
    fi
    echo "$(date): ACCEPT" >> /var/log/zkp_filter.log
else
    echo "$(date): No proof, delivering" >> /var/log/zkp_filter.log
fi
FILENAME="$(date +%s).V$(printf '%05d' $$)I$(printf '%05x' $RANDOM)M$(printf '%05d' $RANDOM).$(hostname)"
cp "$TMPFILE" "$MAILDIR/$FILENAME"
chown ppe:ppe "$MAILDIR/$FILENAME"
chmod 660 "$MAILDIR/$FILENAME"
echo "$(date): Delivered $FILENAME" >> /var/log/zkp_filter.log
rm -f "$TMPFILE"
exit 0
