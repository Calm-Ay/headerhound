# HeaderHound

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-Security%20Tool-red?style=for-the-badge&logo=shield)
![Use Case](https://img.shields.io/badge/Use%20Case-Recon%20%7C%20Bug%20Bounty-orange?style=for-the-badge)

> A Python-based web header and misconfiguration scanner built for security testing, recon, and bug bounty workflows. Fast, lightweight, and easy to understand.

---

## Overview

HeaderHound helps you quickly inspect web targets for missing security headers, weak cookie flags, suspicious CORS behavior, redirect chains, and basic information disclosure. It is intentionally small enough to understand fully, but useful enough to be worth running in real recon workflows.

---

## Features

- Scan a single URL or a file of multiple targets
- Concurrent scanning for fast multi-target input
- **Security Header Checks:**
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **Cookie Flag Analysis:**
  - `Secure`
  - `HttpOnly`
  - `SameSite`
- Detect broad or reflective CORS behavior
- Server/banner disclosure detection
- Redirect chain tracking
- Output in readable **text** or **JSON**
- Severity-based findings summary (`Critical` → `Info`)

---

## Installation

```bash
git clone https://github.com/Calm-Ay/headerhound.git
cd headerhound
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Scan a single target
```bash
python3 -m headerhound.cli --url https://example.com
```

### Scan multiple targets from a file
```bash
python3 -m headerhound.cli --file sample_targets.txt --workers 5
```

### Save output as JSON
```bash
python3 -m headerhound.cli --file sample_targets.txt --workers 5 --format json --output results.json
```

---

## Example Output

```text
Target: https://example.com
Status: ok
Top Severity: HIGH
Final URL: https://example.com/
HTTP Status: 200

Summary:
  - Critical : 0
  - High     : 1
  - Medium   : 3
  - Low      : 2
  - Info     : 1

Findings:
  [HIGH]   CORS reflects supplied Origin header (https://evil.example)
  [MEDIUM] Missing X-Frame-Options
  [MEDIUM] Missing Content-Security-Policy
  [LOW]    Missing Referrer-Policy
```

---

## Project Structure

```text
headerhound/
├── headerhound/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── output.py
│   └── scanner.py
├── sample_targets.txt
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Roadmap

- [ ] TLS certificate checks
- [ ] HTML report output
- [ ] Tech fingerprinting
- [ ] Custom header profiles
- [ ] Retry / rate-limit controls

---

## Disclaimer

> Use only on systems you own or are explicitly authorized to test. Unauthorized scanning of systems is illegal and unethical.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

**Rasaq Ayomide**
Security Researcher | Penetration Tester | AppSec & Endpoint Security
- GitHub: [@Calm-Ay](https://github.com/Calm-Ay)
- Email: ayomiderasq6@gmail.com
