# KeySift

**Offline high-entropy credential forger & local secret sifter.**

Built by Mourad.Soltani

## What you get

- Forge cryptographically secure passwords, API keys, and tokens
- Instant Shannon entropy scoring + strength labels
- Policy checker for passwords (length, case, digit, symbol)
- Local directory sifter that finds high-entropy strings (potential leaked secrets)
- Pure Python, zero external dependencies
- Health checks and unit tests included

## Requirements

- Python 3.8+

## How to run (30 seconds)

```bash
# Health check
python keysift.py health

# Forge a strong password
python keysift.py forge password -l 20 --policy

# Forge an API key
python keysift.py forge apikey

# Score any string
python keysift.py score "MySecret123!"

# Sift current directory for high-entropy secrets
python keysift.py sift .
```

## Buyer notes

Unzip and run immediately. No install, no network, no telemetry.  
All generation uses Python's `secrets` module (CSPRNG).  
Sifting is local-only and never sends data anywhere.

---

Built by Mourad.Soltani
