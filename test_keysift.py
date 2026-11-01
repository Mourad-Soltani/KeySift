"""Health and functional tests for KeySift.
Built by Mourad.Soltani
"""

import subprocess
import sys
import tempfile
from pathlib import Path

# Allow importing from the script directory
sys.path.insert(0, str(Path(__file__).parent))

from keysift import (
    calculate_entropy,
    generate_password,
    generate_api_key,
    generate_token,
    check_policy,
    strength_label,
    sift_file,
)


def test_entropy_empty():
    assert calculate_entropy("") == 0.0


def test_entropy_positive():
    s = "Abcdef123!@#"
    assert calculate_entropy(s) > 40


def test_strength_labels():
    assert strength_label(20) == "WEAK"
    assert strength_label(30) == "FAIR"
    assert strength_label(50) == "STRONG"
    assert strength_label(70) == "VERY STRONG"


def test_generate_password_length():
    pw = generate_password(20)
    assert len(pw) == 20


def test_generate_apikey_prefix():
    key = generate_api_key(16)
    assert key.startswith("sk_")
    assert len(key) > 16


def test_generate_token_urlsafe():
    tok = generate_token(16)
    assert len(tok) > 0
    # token_urlsafe produces URL-safe chars
    assert all(c.isalnum() or c in "-_" for c in tok)


def test_policy_pass():
    strong = "Abcdef123!@#Strong"
    assert check_policy(strong) == []


def test_policy_fail_length():
    issues = check_policy("Short1!", min_length=12)
    assert any("Length" in i for i in issues)


def test_cli_health():
    result = subprocess.run(
        [sys.executable, "keysift.py", "health"],
        cwd=Path(__file__).parent,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout
    assert "Mourad.Soltani" in result.stdout


def test_cli_forge_password():
    result = subprocess.run(
        [sys.executable, "keysift.py", "forge", "password", "-l", "12"],
        cwd=Path(__file__).parent,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    lines = result.stdout.strip().splitlines()
    assert len(lines[0]) == 12


def test_sift_detects_secret():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        secret = "sk_test_VeryHighEntropySecretStringHere1234567890ABCDEF"
        f = tmp_path / "config.env"
        f.write_text(f"API_KEY={secret}\n")
        findings = sift_file(f, min_entropy=50.0)
        assert len(findings) >= 1
        assert findings[0]["entropy"] > 50
