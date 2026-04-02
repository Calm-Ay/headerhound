# HeaderHound

HeaderHound is a beginner-friendly but practical Python CLI for spotting common web security header and response misconfigurations.

## Features

- Scan a single URL or a file of URLs
- Concurrent scanning for multi-target input
- Follow redirects and report redirect chains
- Check common security headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Review cookies for missing `Secure`, `HttpOnly`, and `SameSite`
- Detect broad or reflective CORS behavior
- Report server/banner disclosure
- Output as readable text or JSON
- Severity summaries for findings

## Install

```bash
cd headerhound
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Scan one URL
```bash
python3 -m headerhound.cli --url https://example.com
```

### Scan multiple URLs from a file
```bash
python3 -m headerhound.cli --file sample_targets.txt
```

### Use concurrency
```bash
python3 -m headerhound.cli --file sample_targets.txt --workers 10
```

### JSON output
```bash
python3 -m headerhound.cli --url https://example.com --format json
```

### Save results
```bash
python3 -m headerhound.cli --file sample_targets.txt --format json --output results.json
```

## What it checks

- Missing recommended security headers
- Cookie flag weaknesses
- Wildcard or reflective CORS behavior
- Server disclosure through `Server` or `X-Powered-By`
- Redirect chain summary
- Severity distribution across findings

## Example output

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
```

## Roadmap

- HTML report output
- TLS certificate summary
- Tech fingerprinting
- Custom header profiles
- Rate limiting and retry controls

## Disclaimer

Use only on systems you own or are authorized to test.
