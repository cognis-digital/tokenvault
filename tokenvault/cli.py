"""TOKENVAULT command-line interface.

Examples
--------
  # Scan a file for card numbers (CI-friendly: exits 2 if any are found)
  tokenvault scan demos/01-basic/payments.log

  # Tokenize every PAN found in a file, writing the redacted copy out
  export TOKENVAULT_KEY='super-secret-key'
  tokenvault tokenize demos/01-basic/payments.log --vault vault.json

  # Reverse a single token (audited)
  tokenvault detokenize 4532015199999704 --vault vault.json

  # Inspect the audit trail as JSON for your SIEM
  tokenvault audit --vault vault.json --format json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from typing import List, Optional

from tokenvault import TOOL_NAME, TOOL_VERSION
from tokenvault.core import (
    Vault,
    detect_pans,
    load_key,
    mask_pan,
)


def _print_table(rows: List[List[str]], headers: List[str]) -> None:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for r in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _cmd_scan(args) -> int:
    text = _read_input(args.input)
    hits = detect_pans(text, require_luhn=not args.include_invalid)
    if args.format == "json":
        print(json.dumps({"input": args.input, "count": len(hits),
                          "findings": [h.to_dict() for h in hits]}, indent=2))
    else:
        if not hits:
            print("No PANs detected.")
        else:
            rows = [[h.masked, str(len(h.digits)), "yes" if h.luhn_valid else "NO",
                     str(h.start)] for h in hits]
            _print_table(rows, ["masked", "len", "luhn", "offset"])
            print(f"\n{len(hits)} PAN(s) detected.")
    # CI gate: finding cardholder data is a failure condition.
    return 2 if hits else 0


def _cmd_tokenize(args) -> int:
    key = load_key(args.key)
    vault = Vault(key, args.vault, args.audit, keep_bin=args.keep_bin)
    text = _read_input(args.input)
    new_text, count = vault.tokenize_text(text, actor=args.actor, source=args.input)
    vault.save()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(new_text)
    if args.format == "json":
        print(json.dumps({"tokenized": count, "vault_size": vault.size,
                          "output": args.output or "-"}, indent=2))
        if not args.output:
            sys.stderr.write(new_text)
    else:
        if not args.output:
            sys.stdout.write(new_text)
            if new_text and not new_text.endswith("\n"):
                sys.stdout.write("\n")
        print(f"Tokenized {count} PAN(s); vault now holds {vault.size}.",
              file=sys.stderr)
    return 0


def _cmd_detokenize(args) -> int:
    key = load_key(args.key)
    vault = Vault(key, args.vault, args.audit, keep_bin=args.keep_bin)
    pan = vault.detokenize(args.token, actor=args.actor, source="cli")
    vault.save()
    if args.format == "json":
        print(json.dumps({"token": args.token, "found": pan is not None,
                          "pan": pan, "masked": mask_pan(pan) if pan else None}))
    else:
        if pan is None:
            print("Token not found in vault (access denied / unknown token).")
        else:
            print(pan)
    return 0 if pan is not None else 3


def _cmd_audit(args) -> int:
    key = load_key(args.key)
    vault = Vault(key, args.vault, args.audit, keep_bin=args.keep_bin)
    events = vault.read_audit()
    if args.op:
        events = [e for e in events if e.op == args.op]
    if args.format == "json":
        print(json.dumps([e.to_dict() for e in events], indent=2))
    else:
        if not events:
            print("No audit events.")
        else:
            rows = []
            for e in events:
                ts = _dt.datetime.fromtimestamp(e.ts).strftime("%Y-%m-%d %H:%M:%S")
                rows.append([ts, e.op, e.actor, e.token, e.masked_pan or "-"])
            _print_table(rows, ["time", "op", "actor", "token", "masked_pan"])
            print(f"\n{len(events)} audit event(s).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="PCI tokenization CLI: swap PANs for format-preserving "
                    "tokens with an access audit trail.",
        epilog="Set TOKENVAULT_KEY or pass --key. See subcommand --help.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    def add_vault_opts(sp):
        sp.add_argument("--key", help="vault key (or @file, or $TOKENVAULT_KEY)")
        sp.add_argument("--vault", default="vault.json", help="vault file path")
        sp.add_argument("--audit", default="audit.log", help="audit JSONL path")
        sp.add_argument("--keep-bin", type=int, default=6,
                        help="leading digits to preserve (BIN, default 6)")
        sp.add_argument("--actor", default="cli", help="actor name for the audit log")

    sp = sub.add_parser("scan", help="detect PANs in a file (CI gate)")
    sp.add_argument("input", help="input file, or - for stdin")
    sp.add_argument("--include-invalid", action="store_true",
                    help="also report numbers failing the Luhn check")
    sp.set_defaults(func=_cmd_scan)

    sp = sub.add_parser("tokenize", help="replace PANs with tokens")
    sp.add_argument("input", help="input file, or - for stdin")
    sp.add_argument("-o", "--output", help="write redacted output here (else stdout)")
    add_vault_opts(sp)
    sp.set_defaults(func=_cmd_tokenize)

    sp = sub.add_parser("detokenize", help="reverse a token back to its PAN")
    sp.add_argument("token", help="the token to reverse")
    add_vault_opts(sp)
    sp.set_defaults(func=_cmd_detokenize)

    sp = sub.add_parser("audit", help="show the access audit trail")
    sp.add_argument("--op", choices=["tokenize", "detokenize", "detokenize_denied"],
                    help="filter by operation")
    add_vault_opts(sp)
    sp.set_defaults(func=_cmd_audit)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
