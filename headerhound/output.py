from __future__ import annotations

import json
from typing import Any

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def render_finding(finding: dict[str, str]) -> str:
    label = SEVERITY_LABELS.get(finding.get("severity", "info"), "INFO")
    detail = f" ({finding['detail']})" if finding.get("detail") else ""
    return f"  - [{label}] {finding.get('title')}{detail}"


def render_summary(summary: dict[str, int]) -> list[str]:
    return [
        "Summary:",
        f"  - Critical: {summary.get('critical', 0)}",
        f"  - High: {summary.get('high', 0)}",
        f"  - Medium: {summary.get('medium', 0)}",
        f"  - Low: {summary.get('low', 0)}",
        f"  - Info: {summary.get('info', 0)}",
    ]


def format_text(results: list[dict[str, Any]]) -> str:
    blocks = []
    for result in results:
        lines = [
            f"Target: {result.get('url')}",
            f"Status: {result.get('status')}",
            f"Top Severity: {SEVERITY_LABELS.get(result.get('top_severity', 'info'), 'INFO')}",
        ]

        if result.get("status") == "error":
            lines.append(f"Error: {result.get('error')}")
            blocks.append("\n".join(lines))
            continue

        lines.extend(
            [
                f"Final URL: {result.get('final_url')}",
                f"HTTP Status: {result.get('status_code')}",
            ]
        )
        lines.extend(render_summary(result.get("summary", {})))
        lines.append("Findings:")

        findings = result.get("findings") or []
        if findings:
            lines.extend([render_finding(finding) for finding in findings])
        else:
            lines.append("  - [INFO] No obvious issues found by current checks")

        lines.append("Redirect Chain:")
        for item in result.get("redirect_chain", []):
            location = f" -> {item['location']}" if item.get("location") else ""
            lines.append(f"  - {item['status_code']} {item['url']}{location}")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def format_json(results: list[dict[str, Any]]) -> str:
    return json.dumps(results, indent=2)
