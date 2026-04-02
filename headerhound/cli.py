from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .output import format_json, format_text
from .scanner import scan_url


def load_targets(url: str | None, file_path: str | None) -> list[str]:
    targets = []
    if url:
        targets.append(url)
    if file_path:
        for line in Path(file_path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    seen = set()
    deduped = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            deduped.append(target)
    return deduped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HeaderHound - web header misconfiguration scanner")
    parser.add_argument("--url", help="Single URL to scan")
    parser.add_argument("--file", help="File containing URLs to scan")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--output", help="Write results to file")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent workers for multi-target scans")
    return parser


def run_scans(targets: list[str], timeout: int, workers: int) -> list[dict]:
    if len(targets) <= 1:
        return [scan_url(targets[0], timeout=timeout)] if targets else []

    results = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_map = {executor.submit(scan_url, target, timeout): target for target in targets}
        for future in as_completed(future_map):
            results.append(future.result())

    result_order = {result["input"]: result for result in results}
    return [result_order[target] for target in targets if target in result_order]


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("provide --url or --file")

    targets = load_targets(args.url, args.file)
    results = run_scans(targets, timeout=args.timeout, workers=args.workers)

    rendered = format_json(results) if args.format == "json" else format_text(results)

    if args.output:
        Path(args.output).write_text(rendered)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
