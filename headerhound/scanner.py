from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "content-security-policy": ("high", "Missing Content-Security-Policy"),
    "strict-transport-security": ("medium", "Missing Strict-Transport-Security"),
    "x-frame-options": ("medium", "Missing X-Frame-Options"),
    "x-content-type-options": ("medium", "Missing X-Content-Type-Options"),
    "referrer-policy": ("low", "Missing Referrer-Policy"),
    "permissions-policy": ("low", "Missing Permissions-Policy"),
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def make_finding(severity: str, title: str, detail: str | None = None) -> dict[str, str]:
    finding = {"severity": severity, "title": title}
    if detail:
        finding["detail"] = detail
    return finding


def parse_set_cookie_headers(response: requests.Response) -> list[str]:
    raw = []
    header_obj = getattr(response.raw, "headers", None)
    if header_obj and hasattr(header_obj, "get_all"):
        raw = header_obj.get_all("Set-Cookie") or []
    if raw:
        return raw

    fallback = response.headers.get("Set-Cookie")
    return [fallback] if fallback else []


def analyze_cookies(set_cookie_headers: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    cookies = []
    findings = []
    for header in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            continue

        for morsel in cookie.values():
            attrs = {k.lower(): v for k, v in morsel.items() if v}
            cookie_findings = []

            if "secure" not in attrs:
                cookie_findings.append(make_finding("medium", f"Cookie {morsel.key} missing Secure"))
            if "httponly" not in attrs:
                cookie_findings.append(make_finding("medium", f"Cookie {morsel.key} missing HttpOnly"))
            if "samesite" not in attrs:
                cookie_findings.append(make_finding("low", f"Cookie {morsel.key} missing SameSite"))

            cookies.append(
                {
                    "name": morsel.key,
                    "attributes": attrs,
                    "findings": cookie_findings,
                }
            )
            findings.extend(cookie_findings)
    return cookies, findings


def analyze_headers(response: requests.Response, origin: str | None = None) -> list[dict[str, str]]:
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []

    for header, (severity, message) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(make_finding(severity, message))

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    if server:
        findings.append(make_finding("info", "Server header exposed", server))
    if powered_by:
        findings.append(make_finding("info", "X-Powered-By exposed", powered_by))

    aco = headers.get("access-control-allow-origin")
    acc = headers.get("access-control-allow-credentials")
    if aco == "*":
        findings.append(make_finding("medium", "CORS allows any origin (*)"))
    if origin and aco and aco == origin:
        findings.append(make_finding("high", "CORS reflects supplied Origin header", origin))
    if aco == "*" and acc and acc.lower() == "true":
        findings.append(make_finding("high", "Suspicious CORS: wildcard origin with credentials=true"))

    return findings


def build_redirect_chain(response: requests.Response) -> list[dict[str, Any]]:
    chain = []
    for item in response.history:
        chain.append(
            {
                "url": item.url,
                "status_code": item.status_code,
                "location": item.headers.get("Location"),
            }
        )
    chain.append({"url": response.url, "status_code": response.status_code, "location": None})
    return chain


def summarize_severity(findings: list[dict[str, str]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info")
        summary[severity] = summary.get(severity, 0) + 1
    return summary


def top_severity(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda item: SEVERITY_ORDER.get(item.get("severity", "info"), 0)).get("severity", "info")


def scan_url(url: str, timeout: int = 10, origin: str = "https://evil.example") -> dict[str, Any]:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    result: dict[str, Any] = {
        "input": url,
        "url": normalized,
        "host": parsed.netloc,
        "status": "ok",
    }

    try:
        response = requests.get(
            normalized,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "HeaderHound/0.2",
                "Origin": origin,
            },
        )
        set_cookie_headers = parse_set_cookie_headers(response)
        cookies, cookie_findings = analyze_cookies(set_cookie_headers)
        findings = analyze_headers(response, origin=origin)
        findings.extend(cookie_findings)
        findings = sorted(findings, key=lambda item: SEVERITY_ORDER.get(item["severity"], 0), reverse=True)

        result.update(
            {
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "redirect_chain": build_redirect_chain(response),
                "cookies": cookies,
                "findings": findings,
                "summary": summarize_severity(findings),
                "top_severity": top_severity(findings),
            }
        )
    except requests.RequestException as exc:
        result.update(
            {
                "status": "error",
                "error": str(exc),
                "findings": [],
                "summary": summarize_severity([]),
                "top_severity": "info",
            }
        )

    return result
