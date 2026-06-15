"""Hardening tests for TOKENVAULT — error paths, edge cases, bad input."""
from __future__ import annotations

import os
import sys
import warnings

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from tokenvault.core import (
    Vault,
    detect_pans,
    load_key,
    tokenize_pan,
)
from tokenvault.cli import main

KEY = b"harden-test-key"


# ---------------------------------------------------------------------------
# load_key
# ---------------------------------------------------------------------------

def test_load_key_from_env(monkeypatch):
    monkeypatch.setenv("TOKENVAULT_KEY", "env-secret")
    assert load_key(None) == b"env-secret"


def test_load_key_inline():
    assert load_key("mykey") == b"mykey"


def test_load_key_at_file(tmp_path):
    kf = tmp_path / "mykey.bin"
    kf.write_bytes(b"file-key\n")
    assert load_key(f"@{kf}") == b"file-key"


def test_load_key_at_file_missing():
    with pytest.raises(FileNotFoundError, match="key file not found"):
        load_key("@/nonexistent/path/to/key.bin")


def test_load_key_at_file_empty(tmp_path):
    kf = tmp_path / "empty.bin"
    kf.write_bytes(b"   \n")
    with pytest.raises(ValueError, match="empty"):
        load_key(f"@{kf}")


def test_load_key_no_source(monkeypatch):
    monkeypatch.delenv("TOKENVAULT_KEY", raising=False)
    with pytest.raises(ValueError, match="no key provided"):
        load_key(None)


# ---------------------------------------------------------------------------
# Vault._load — malformed vault file
# ---------------------------------------------------------------------------

def test_vault_malformed_json(tmp_path):
    vp = tmp_path / "bad.json"
    vp.write_text("not-json{{{", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        Vault(KEY, str(vp), str(tmp_path / "a.log"))


def test_vault_wrong_json_type(tmp_path):
    vp = tmp_path / "bad.json"
    vp.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected format"):
        Vault(KEY, str(vp), str(tmp_path / "a.log"))


# ---------------------------------------------------------------------------
# Vault.read_audit — corrupted audit lines are skipped with a warning
# ---------------------------------------------------------------------------

def test_read_audit_skips_corrupt_lines(tmp_path):
    vp = str(tmp_path / "v.json")
    ap = str(tmp_path / "a.log")
    v = Vault(KEY, vp, ap)
    v.tokenize("4532015112830366", actor="test")
    v.save()

    # Inject a bad line into the audit log between two good lines.
    good_line = open(ap, encoding="utf-8").read().strip()
    with open(ap, "w", encoding="utf-8") as fh:
        fh.write(good_line + "\n")
        fh.write("CORRUPTED_LINE_NOT_JSON\n")
        fh.write(good_line + "\n")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        events = v.read_audit()

    assert len(events) == 2  # two good lines survived
    assert any("malformed" in str(w.message) for w in caught)


# ---------------------------------------------------------------------------
# detect_pans — edge cases
# ---------------------------------------------------------------------------

def test_detect_pans_empty_string():
    assert detect_pans("") == []


def test_detect_pans_no_numbers():
    assert detect_pans("hello world, no card here") == []


def test_detect_pans_short_number():
    # 11-digit number must not match (below PAN floor)
    assert detect_pans("12345678901") == []


def test_detect_pans_require_luhn_filters_invalid():
    # A 16-digit string failing Luhn should be excluded when require_luhn=True
    assert detect_pans("4532015112830367") == []  # last digit wrong
    hits = detect_pans("4532015112830367", require_luhn=False)
    assert len(hits) == 1


# ---------------------------------------------------------------------------
# tokenize_pan — input validation
# ---------------------------------------------------------------------------

def test_tokenize_pan_rejects_short():
    with pytest.raises(ValueError, match="12-19 digits"):
        tokenize_pan("12345", KEY)


def test_tokenize_pan_rejects_non_digits():
    with pytest.raises(ValueError, match="12-19 digits"):
        tokenize_pan("abcdefghijklmnop", KEY)


def test_tokenize_pan_rejects_empty():
    with pytest.raises(ValueError):
        tokenize_pan("", KEY)


# ---------------------------------------------------------------------------
# CLI — missing file exits 1 with message on stderr
# ---------------------------------------------------------------------------

def test_cli_scan_missing_file(capsys):
    rc = main(["scan", "/nonexistent/path/to/file.txt"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "error" in err.lower() or "not found" in err.lower() or err


def test_cli_no_command(capsys):
    rc = main([])
    assert rc == 1


def test_cli_tokenize_missing_key(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("TOKENVAULT_KEY", raising=False)
    infile = tmp_path / "in.txt"
    infile.write_text("no PANs here", encoding="utf-8")
    vp = str(tmp_path / "v.json")
    rc = main(["tokenize", str(infile), "--vault", vp])
    assert rc == 1
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_tokenize_corrupt_vault(monkeypatch, tmp_path, capsys):
    vp = tmp_path / "v.json"
    vp.write_text("{not valid json}", encoding="utf-8")
    infile = tmp_path / "in.txt"
    infile.write_text("hello world", encoding="utf-8")
    rc = main([
        "tokenize", str(infile),
        "--vault", str(vp),
        "--key", "testkey",
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "error" in err.lower()
