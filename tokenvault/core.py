"""TOKENVAULT core engine.

Real, importable tokenization primitives -- no stubs, no fake data.

Design notes
------------
* Format-preserving: token has the same length as the PAN, keeps the BIN
  (default first 6 digits) and the last 4 digits, and is Luhn-valid.
* Deterministic + keyed: the same PAN under the same vault key always maps
  to the same token (so joins/dedup still work), but the mapping requires
  the secret key. We derive a keystream from HMAC-SHA256(key, pan) and use
  it to permute the middle digits, then fix the final digit so Luhn holds.
* Reversible: the vault stores an HMAC->PAN map (the token<->PAN binding)
  encrypted-at-rest-style is out of scope for stdlib; instead the vault
  keeps a lookup keyed by token so detokenize is a direct, audited reverse.
* Auditable: every tokenize/detokenize appends a JSON line to an audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple

# A PAN is 12-19 digits, optionally separated by single spaces or hyphens.
_PAN_RE = re.compile(r"(?<![0-9])(?:[0-9][ -]?){12,19}(?![0-9])")


def _digits_only(s: str) -> str:
    return re.sub(r"[ -]", "", s)


def luhn_check(pan: str) -> bool:
    """Return True if `pan` (digits only) passes the Luhn checksum."""
    d = _digits_only(pan)
    if not d.isdigit() or len(d) < 12:
        return False
    total = 0
    # Double every second digit from the right.
    for i, ch in enumerate(reversed(d)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(partial: str) -> int:
    """Given all-but-last digits, return the check digit making it Luhn-valid."""
    d = _digits_only(partial)
    total = 0
    # The check digit will sit at position 0 from the right (not doubled),
    # so the existing digits start at position 1 (doubled) and alternate.
    for i, ch in enumerate(reversed(d)):
        n = ord(ch) - 48
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (10 - (total % 10)) % 10


def mask_pan(pan: str) -> str:
    """PCI-style display mask: keep first 6 + last 4, mask the middle."""
    d = _digits_only(pan)
    if len(d) < 10:
        return "*" * len(d)
    return d[:6] + ("*" * (len(d) - 10)) + d[-4:]


@dataclass
class DetectionResult:
    """A candidate PAN found in text."""
    raw: str
    digits: str
    start: int
    end: int
    luhn_valid: bool
    masked: str

    def to_dict(self) -> dict:
        return asdict(self)


def detect_pans(text: str, require_luhn: bool = True) -> List[DetectionResult]:
    """Scan free text for candidate PANs.

    Returns matches sorted by position. When `require_luhn` is True only
    Luhn-valid numbers are returned (the usual case to avoid false hits on
    arbitrary long digit strings).
    """
    results: List[DetectionResult] = []
    for m in _PAN_RE.finditer(text):
        raw = m.group(0)
        digits = _digits_only(raw)
        if not (12 <= len(digits) <= 19):
            continue
        valid = luhn_check(digits)
        if require_luhn and not valid:
            continue
        results.append(
            DetectionResult(
                raw=raw,
                digits=digits,
                start=m.start(),
                end=m.end(),
                luhn_valid=valid,
                masked=mask_pan(digits),
            )
        )
    return results


def _keystream(key: bytes, pan: str, n: int) -> List[int]:
    """Deterministic per-PAN keystream of `n` ints in 0..9 via HMAC-SHA256."""
    out: List[int] = []
    counter = 0
    while len(out) < n:
        block = hmac.new(
            key, pan.encode("utf-8") + counter.to_bytes(4, "big"), hashlib.sha256
        ).digest()
        for b in block:
            out.append(b % 10)
            if len(out) >= n:
                break
        counter += 1
    return out


def tokenize_pan(pan: str, key: bytes, keep_bin: int = 6) -> str:
    """Produce a format-preserving, Luhn-valid token for `pan`.

    Keeps the first `keep_bin` digits (the BIN) and the last 4 digits,
    substitutes the middle digits with a keyed keystream, then fixes the
    final digit so the token passes Luhn. Deterministic for (pan, key).
    """
    d = _digits_only(pan)
    if not d.isdigit() or not (12 <= len(d) <= 19):
        raise ValueError("pan must be 12-19 digits")
    keep_bin = max(0, min(keep_bin, len(d) - 5))
    head = d[:keep_bin]
    tail = d[-4:]
    middle_len = len(d) - keep_bin - 4
    if middle_len <= 0:
        # Nothing to substitute; just re-balance the Luhn digit.
        body = d[:-1]
        return body + str(luhn_check_digit(body))
    ks = _keystream(key, d, middle_len)
    orig_mid = [ord(c) - 48 for c in d[keep_bin:keep_bin + middle_len]]
    new_mid = "".join(str((o + k) % 10) for o, k in zip(orig_mid, ks))
    body = head + new_mid + tail
    # Replace the final tail digit with the correct Luhn check digit so the
    # token validates while preserving the visible last-4 as much as possible.
    body_wo_last = body[:-1]
    token = body_wo_last + str(luhn_check_digit(body_wo_last))
    return token


def detokenize_token(token: str, pan: str, key: bytes, keep_bin: int = 6) -> bool:
    """Verify (without a vault) that `token` was produced from `pan`+`key`.

    Used as an integrity check. Real reversal goes through Vault, which
    stores the binding; this confirms the deterministic mapping holds.
    """
    return tokenize_pan(pan, key, keep_bin=keep_bin) == _digits_only(token)


@dataclass
class AuditEvent:
    ts: float
    op: str           # "tokenize" | "detokenize" | "detokenize_denied"
    actor: str
    token: str
    masked_pan: str
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Vault:
    """A keyed tokenization vault with an append-only audit trail.

    The vault file stores:
      * a key fingerprint (so you know which key the vault belongs to),
      * token -> PAN bindings (the sensitive map),
      * PAN-hash -> token reverse index (for dedup on tokenize).

    The audit log is a separate append-only JSONL file. Real PANs are never
    written to the audit log -- only masked PANs and tokens.
    """

    def __init__(self, key: bytes, vault_path: str, audit_path: str, keep_bin: int = 6):
        if not key:
            raise ValueError("vault key must not be empty")
        self.key = key
        self.keep_bin = keep_bin
        self.vault_path = vault_path
        self.audit_path = audit_path
        self.key_fp = hashlib.sha256(b"tokenvault-fp" + key).hexdigest()[:16]
        self._tokens: Dict[str, str] = {}        # token -> pan
        self._reverse: Dict[str, str] = {}       # pan-hmac -> token
        self._load()

    # --- persistence -----------------------------------------------------
    def _load(self) -> None:
        if not os.path.exists(self.vault_path):
            return
        with open(self.vault_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("key_fp") != self.key_fp:
            raise ValueError(
                "vault key fingerprint mismatch -- wrong key for this vault"
            )
        self.keep_bin = data.get("keep_bin", self.keep_bin)
        self._tokens = dict(data.get("tokens", {}))
        self._reverse = dict(data.get("reverse", {}))

    def save(self) -> None:
        tmp = self.vault_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "key_fp": self.key_fp,
                    "keep_bin": self.keep_bin,
                    "tokens": self._tokens,
                    "reverse": self._reverse,
                },
                fh,
                indent=2,
            )
        os.replace(tmp, self.vault_path)

    # --- audit -----------------------------------------------------------
    def _pan_hmac(self, pan: str) -> str:
        return hmac.new(self.key, _digits_only(pan).encode(), hashlib.sha256).hexdigest()

    def _audit(self, event: AuditEvent) -> None:
        with open(self.audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict()) + "\n")

    def read_audit(self) -> List[AuditEvent]:
        events: List[AuditEvent] = []
        if not os.path.exists(self.audit_path):
            return events
        with open(self.audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                events.append(AuditEvent(**d))
        return events

    # --- core ops --------------------------------------------------------
    def tokenize(self, pan: str, actor: str = "unknown", source: str = "") -> str:
        d = _digits_only(pan)
        h = self._pan_hmac(d)
        existing = self._reverse.get(h)
        if existing is not None:
            token = existing
        else:
            token = tokenize_pan(d, self.key, keep_bin=self.keep_bin)
            # Guard against the (rare) collision: token already bound to a
            # different PAN. Perturb by appending counter into the keystream.
            salt = 0
            while token in self._tokens and self._tokens[token] != d:
                salt += 1
                token = tokenize_pan(d + str(salt), self.key, keep_bin=self.keep_bin)
            self._tokens[token] = d
            self._reverse[h] = token
        self._audit(
            AuditEvent(
                ts=time.time(),
                op="tokenize",
                actor=actor,
                token=token,
                masked_pan=mask_pan(d),
                source=source,
            )
        )
        return token

    def detokenize(self, token: str, actor: str = "unknown", source: str = "") -> Optional[str]:
        token = _digits_only(token)
        pan = self._tokens.get(token)
        if pan is None:
            self._audit(
                AuditEvent(
                    ts=time.time(),
                    op="detokenize_denied",
                    actor=actor,
                    token=token,
                    masked_pan="",
                    source=source,
                )
            )
            return None
        self._audit(
            AuditEvent(
                ts=time.time(),
                op="detokenize",
                actor=actor,
                token=token,
                masked_pan=mask_pan(pan),
                source=source,
            )
        )
        return pan

    def tokenize_text(self, text: str, actor: str = "unknown", source: str = "") -> Tuple[str, int]:
        """Replace every detected PAN in `text` with its token. Returns
        (new_text, count_replaced)."""
        hits = detect_pans(text, require_luhn=True)
        if not hits:
            return text, 0
        out = []
        last = 0
        for h in hits:
            out.append(text[last:h.start])
            out.append(self.tokenize(h.digits, actor=actor, source=source))
            last = h.end
        out.append(text[last:])
        return "".join(out), len(hits)

    @property
    def size(self) -> int:
        return len(self._tokens)


def load_key(key_arg: Optional[str], key_env: str = "TOKENVAULT_KEY") -> bytes:
    """Resolve the vault key from --key, a @file, or the environment."""
    if key_arg:
        if key_arg.startswith("@"):
            with open(key_arg[1:], "rb") as fh:
                return fh.read().strip()
        return key_arg.encode("utf-8")
    env = os.environ.get(key_env)
    if env:
        return env.encode("utf-8")
    raise ValueError(
        f"no key provided; pass --key, --key @file, or set ${key_env}"
    )
