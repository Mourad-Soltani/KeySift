# Buyer notes — KeySift

**What you get**
- Single-file CLI: `keysift.py`
- Full source, tests, LICENSE, README
- Offline password / API key / token forger with entropy scoring
- Local secret sifter (scans .env, .json, code files for high-entropy strings)

**How to run**
```bash
python keysift.py health
python keysift.py forge password --policy
python keysift.py sift /path/to/project
```

**Requirements**
Python 3.8 or newer. No pip packages needed.

Built by Mourad.Soltani
