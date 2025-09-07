"""Smoke tests for TOKENVAULT. No network. Runs against the real demo file."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tokenvault import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Vault,
    detect_pans,
    luhn_check,
    luhn_check_digit,
    tokenize_pan,
    detokenize_token,
    mask_pan,
)
from tokenvault.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "payments.log")
KEY = b"unit-test-key"


def test_meta():
    assert TOOL_NAME == "tokenvault"
    assert TOOL_VERSION.count(".") == 2


def test_luhn():
    assert luhn_check("4532015112830366")
    assert luhn_check("5425233430109903")
    assert luhn_check("374245455400126")
    assert not luhn_check("4532015112830367")
    # check-digit derivation is consistent with validation
    body = "453201511283036"
    assert luhn_check(body + str(luhn_check_digit(body)))


def test_detect_on_demo():
    with open(DEMO, encoding="utf-8") as fh:
        text = fh.read()
    hits = detect_pans(text)
    # Exactly the three valid test cards; the 13-digit order id is excluded.
    assert len(hits) == 3
    found = {h.digits for h in hits}
    assert "4532015112830366" in found
    assert "5425233430109903" in found
    assert "374245455400126" in found
    assert all(h.luhn_valid for h in hits)
    # order id must not be picked up
    assert "1002003004005" not in found


def test_tokenize_is_format_preserving_and_luhn_valid():
    pan = "4532015112830366"
    tok = tokenize_pan(pan, KEY)
    assert len(tok) == len(pan)
    assert tok[:6] == pan[:6]          # BIN preserved
    assert tok != pan                   # actually changed
    assert luhn_check(tok)              # token still validates
    # deterministic for the same (pan, key)
    assert tokenize_pan(pan, KEY) == tok
    # key matters
    assert tokenize_pan(pan, b"other-key") != tok
    assert detokenize_token(tok, pan, KEY)


def test_mask():
    assert mask_pan("4532015112830366") == "453201******0366"


def test_vault_roundtrip_and_audit(tmp_path):
    vp = str(tmp_path / "v.json")
    ap = str(tmp_path / "a.log")
    v = Vault(KEY, vp, ap)
    pan = "5425233430109903"
    tok = v.tokenize(pan, actor="alice")
    assert tok != pan and len(tok) == len(pan)
    # dedup: same PAN -> same token
    assert v.tokenize(pan, actor="bob") == tok
    v.save()

    # reopen with same key -> can reverse
    v2 = Vault(KEY, vp, ap)
    assert v2.detokenize(tok, actor="carol") == pan
    # unknown token is denied (returns None) and logged
    assert v2.detokenize("0000000000000000", actor="carol") is None
    v2.save()

    events = v2.read_audit()
    ops = [e.op for e in events]
    assert ops.count("tokenize") == 2
    assert "detokenize" in ops
    assert "detokenize_denied" in ops
    # the clear PAN must never appear in the audit trail
    raw = open(ap, encoding="utf-8").read()
    assert pan not in raw
    assert mask_pan(pan) in raw


def test_wrong_key_rejected(tmp_path):
    vp = str(tmp_path / "v.json")
    ap = str(tmp_path / "a.log")
    Vault(KEY, vp, ap).save()
    try:
        Vault(b"different", vp, ap)
        assert False, "expected key fingerprint mismatch"
    except ValueError as e:
        assert "fingerprint" in str(e)


def test_tokenize_text_redacts(tmp_path):
    vp = str(tmp_path / "v.json")
    ap = str(tmp_path / "a.log")
    v = Vault(KEY, vp, ap)
    with open(DEMO, encoding="utf-8") as fh:
        text = fh.read()
    new_text, count = v.tokenize_text(text, actor="job")
    assert count == 3
    # original PANs gone
    assert "4532015112830366" not in new_text
    assert "5425233430109903" not in new_text
    # redacted output scans clean of the originals
    remaining = {h.digits for h in detect_pans(new_text)}
    assert "4532015112830366" not in remaining


def test_cli_scan_exit_code(capsys):
    rc = main(["--format", "json", "scan", DEMO])
    out = capsys.readouterr().out
    assert rc == 2          # findings -> CI gate failure
    assert '"count": 3' in out


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert TOOL_VERSION in capsys.readouterr().out
