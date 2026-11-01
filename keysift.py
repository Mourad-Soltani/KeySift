#!/usr/bin/env python3
"""
KeySift — Offline high-entropy credential forger & local secret sifter.
Built by Mourad.Soltani

Generates cryptographically secure passwords, API keys, and tokens with
entropy scoring and policy checks. Scans local files for high-entropy strings
that may be leaked secrets.
"""

import argparse
import math
import os
import re
import secrets
import string
import sys
from pathlib import Path

# Signature
__author__ = "Mourad.Soltani"
__version__ = "1.0.0"


def calculate_entropy(s: str) -> float:
    """Shannon entropy in bits per character, then total bits."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy_per_char = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy_per_char * length


def strength_label(entropy: float) -> str:
    if entropy < 28:
        return "WEAK"
    if entropy < 36:
        return "FAIR"
    if entropy < 60:
        return "STRONG"
    return "VERY STRONG"


def generate_password(length: int = 16, charset: str = None) -> str:
    if charset is None:
        charset = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(charset) for _ in range(length))


def generate_api_key(length: int = 32) -> str:
    # URL-safe base64-like without padding
    alphabet = string.ascii_letters + string.digits + "-_"
    return "sk_" + "".join(secrets.choice(alphabet) for _ in range(length))


def generate_token(length: int = 40) -> str:
    return secrets.token_urlsafe(length)


def check_policy(password: str, min_length: int = 12, require_upper: bool = True,
                 require_lower: bool = True, require_digit: bool = True,
                 require_symbol: bool = True) -> list:
    issues = []
    if len(password) < min_length:
        issues.append(f"Length {len(password)} < {min_length}")
    if require_upper and not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase")
    if require_lower and not re.search(r"[a-z]", password):
        issues.append("Missing lowercase")
    if require_digit and not re.search(r"\d", password):
        issues.append("Missing digit")
    if require_symbol and not re.search(r"[!@#$%^&*\-_=+]", password):
        issues.append("Missing symbol")
    return issues


HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def sift_file(path: Path, min_entropy: float = 80.0) -> list:
    findings = []
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return findings
    for match in HIGH_ENTROPY_RE.finditer(text):
        candidate = match.group(0)
        ent = calculate_entropy(candidate)
        if ent >= min_entropy:
            findings.append({
                "file": str(path),
                "value_preview": candidate[:8] + "..." + candidate[-4:] if len(candidate) > 16 else candidate,
                "length": len(candidate),
                "entropy": round(ent, 1),
                "line": text[:match.start()].count("\n") + 1
            })
    return findings


def sift_directory(root: Path, extensions=None, min_entropy: float = 80.0) -> list:
    if extensions is None:
        extensions = {".env", ".json", ".yml", ".yaml", ".txt", ".py", ".js", ".ts", ".md", ".sh"}
    findings = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            findings.extend(sift_file(p, min_entropy))
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="KeySift — forge high-entropy credentials & sift local secrets. Built by Mourad.Soltani"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # forge
    forge = sub.add_parser("forge", help="Forge a new credential")
    forge.add_argument("type", choices=["password", "apikey", "token"], help="Credential type")
    forge.add_argument("-l", "--length", type=int, default=None, help="Length (default depends on type)")
    forge.add_argument("--policy", action="store_true", help="Run policy check on password")

    # score
    score = sub.add_parser("score", help="Score entropy of a string")
    score.add_argument("value", help="String to score")

    # sift
    sift = sub.add_parser("sift", help="Sift directory for high-entropy secrets")
    sift.add_argument("path", nargs="?", default=".", help="Directory to scan")
    sift.add_argument("--min-entropy", type=float, default=80.0, help="Minimum entropy to report")

    # health
    sub.add_parser("health", help="Health check")

    args = parser.parse_args()

    if args.cmd == "health":
        print(f"KeySift v{__version__} — OK")
        print("Built by Mourad.Soltani")
        return 0

    if args.cmd == "forge":
        if args.type == "password":
            length = args.length or 16
            value = generate_password(length)
            print(value)
            ent = calculate_entropy(value)
            print(f"# entropy: {ent:.1f} bits ({strength_label(ent)})")
            if args.policy:
                issues = check_policy(value)
                if issues:
                    print("# policy issues:", "; ".join(issues))
                else:
                    print("# policy: PASS")
        elif args.type == "apikey":
            length = args.length or 32
            value = generate_api_key(length)
            print(value)
            print(f"# entropy: {calculate_entropy(value):.1f} bits")
        elif args.type == "token":
            length = args.length or 40
            value = generate_token(length)
            print(value)
            print(f"# entropy: {calculate_entropy(value):.1f} bits")
        return 0

    if args.cmd == "score":
        ent = calculate_entropy(args.value)
        print(f"{ent:.1f} bits — {strength_label(ent)}")
        return 0

    if args.cmd == "sift":
        root = Path(args.path)
        if not root.exists():
            print(f"Path not found: {root}", file=sys.stderr)
            return 1
        findings = sift_directory(root, min_entropy=args.min_entropy)
        if not findings:
            print("No high-entropy secrets found.")
            return 0
        for f in findings:
            print(f"{f['file']}:{f['line']}  entropy={f['entropy']}  len={f['length']}  preview={f['value_preview']}")
        print(f"\n{len(findings)} potential secret(s) found.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
