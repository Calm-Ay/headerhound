# HeaderHound

HeaderHound is a Python-based web header and response misconfiguration scanner built for learning, recon, and lightweight security testing.

It helps you quickly inspect web targets for missing security headers, weak cookie flags, suspicious CORS behavior, redirect chains, and basic information disclosure.

## Why this project matters

HeaderHound is intentionally small enough to understand, but useful enough to be worth running.

It is a good starter project for:
- web application security learning
- bug bounty recon workflows
- cloud / edge security basics
- building security tooling in Python

## Features

- Scan a single URL or a file of URLs
- Concurrent scanning for multi-target input
- Check common security headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Review cookies for missing:
  - `Secure`
  - `HttpOnly`
  - `SameSite`
- Detect broad or reflective CORS behavior
- Report server/banner disclosure
- Follow redirects and show redirect chains
- Output in readable text or JSON
- Summarize findings by severity

## Installation

```bash
git clone https://github.com/Calm-Ay/headerhound.git
cd headerhound
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Scan one target
```bash
python3 -m headerhound.cli --url https://example.com
```

### Scan multiple targets
```bash
python3 -m headerhound.cli --file sample_targets.txt --workers 5
```

### Save JSON output
```bash
python3 -m headerhound.cli --file sample_targets.txt --workers 5 --format json --output results.json
```

## Example text output

```text
Target: https://example.com
Status: ok
Top Severity: HIGH
Final URL: https://example.com/
HTTP Status: 200
Summary:
  - Critical: 0
  - High: 1
  - Medium: 3
  - Low: 2
  - Info: 1
Findings:
  - [HIGH] CORS reflects supplied Origin header (https://evil.example)
  - [MEDIUM] Missing X-Frame-Options
  - [LOW] Missing Referrer-Policy
```

## Example JSON output

```bash
python3 -m headerhound.cli --url https://example.com --format json
```

## Project structure

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

## Roadmap

Planned next improvements:
- TLS certificate checks
- HTML report output
- tech fingerprinting
- custom header profiles
- retry / rate-limit controls

## Disclaimer

Use only on systems you own or are explicitly authorized to test.

## License

MIT
