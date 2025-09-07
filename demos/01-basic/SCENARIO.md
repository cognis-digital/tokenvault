# Demo 01 - Basic tokenization & audit

This demo shows TOKENVAULT finding real Primary Account Numbers (PANs) in an
application log, replacing them with format-preserving tokens, and proving
the access trail.

## Input

`payments.log` is a snippet of an application log that accidentally captured
full card numbers (a classic PCI-scope problem). It contains three valid
test PANs (all pass the Luhn checksum) plus a non-card 13-digit order id that
should NOT be treated as a PAN.

The card numbers are standard publicly-documented test PANs:
* `4532015112830366` (Visa, Luhn-valid)
* `5425233430109903` (Mastercard, Luhn-valid)
* `374245455400126`  (Amex, 15-digit, Luhn-valid)

## Steps

```bash
export TOKENVAULT_KEY='demo-secret-key-please-rotate'

# 1. Scan -- CI gate. Exits 2 because cardholder data is present.
python -m tokenvault scan demos/01-basic/payments.log

# 2. Tokenize -- write a redacted copy, recording each op to audit.log
python -m tokenvault tokenize demos/01-basic/payments.log \
    -o redacted.log --vault vault.json --audit audit.log --actor alice

# 3. Verify the redacted copy is now clean (exits 0)
python -m tokenvault scan redacted.log

# 4. Reverse one token (audited)
python -m tokenvault detokenize <token-from-redacted.log> --vault vault.json

# 5. Review who touched what
python -m tokenvault audit --vault vault.json --format json
```

## Expected result

* `scan` reports **3** PANs (the order id is correctly ignored) and exits 2.
* Each token is the SAME length as its PAN, keeps the first 6 + last 4
  digits, and is itself Luhn-valid -- so downstream validators still pass.
* The redacted log scans clean (the tokens differ from the originals, so the
  original PANs are gone).
* The audit log has one `tokenize` event per PAN and a `detokenize` event for
  step 4, with only MASKED PANs recorded -- never the clear PAN.
