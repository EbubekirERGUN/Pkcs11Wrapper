#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HIGHLIGHT_BENCHMARKS = [
    "LoadInitializeGetInfoFinalizeDispose",
    "OpenReadOnlySessionAndGetInfo",
    "GenerateRandom32",
    "EncryptAesCbcPad_1KiB",
    "VerifySha256RsaPkcs_1KiB",
    "GenerateDestroyRsaKeyPair",
]


def main() -> int:
    if len(sys.argv) not in {3, 4}:
        print(
            "Usage: render-benchmark-report.py <summary.json> <output.md> [summary.md]",
            file=sys.stderr,
        )
        return 2

    summary_json_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    summary_markdown_path = Path(sys.argv[3]) if len(sys.argv) == 4 else summary_json_path.with_name("summary.md")

    document = json.loads(summary_json_path.read_text(encoding="utf-8"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_report(document, summary_markdown_path), encoding="utf-8")
    return 0


def build_report(document: dict[str, Any], summary_markdown_path: Path) -> str:
    entries = list(document.get("Entries", []))
    entries_by_name = {entry.get("Benchmark"): entry for entry in entries}
    generated = format_generated_utc(document.get("GeneratedUtc"))
    categories = Counter(entry.get("Category", "Unknown") for entry in entries)
    slowest_entries = sorted(
        entries,
        key=lambda entry: float(entry.get("MeanNanoseconds", 0.0)),
        reverse=True,
    )[:5]

    lines: list[str] = []
    lines.append("# Benchmark run report")
    lines.append("")
    append_run_context(lines)
    lines.append(f"- Generated (UTC): **{generated}**")
    lines.append(
        "- Environment: **{os_name} / {architecture} / SDK {sdk} / Runtime {runtime}**".format(
            os_name=document.get("OperatingSystem", "unknown"),
            architecture=document.get("Architecture", "unknown"),
            sdk=document.get("SdkVersion", "unknown"),
            runtime=document.get("RuntimeVersion", "unknown"),
        )
    )
    lines.append(f"- Host framework: `{document.get('HostFramework', 'unknown')}`")
    lines.append(f"- PKCS#11 module: `{document.get('FixtureModulePath', 'unknown')}`")
    lines.append(
        f"- Benchmarks executed: **{len(entries)}** across **{len(categories)}** categor{'y' if len(categories) == 1 else 'ies'}"
    )
    lines.append("")

    highlight_rows = [entries_by_name[name] for name in HIGHLIGHT_BENCHMARKS if name in entries_by_name]
    if highlight_rows:
        lines.append("## Headline results")
        lines.append("")
        lines.append("| Benchmark | Mean | Category |")
        lines.append("| --- | ---: | --- |")
        for entry in highlight_rows:
            lines.append(
                "| {benchmark} | {mean} | {category} |".format(
                    benchmark=entry.get("Benchmark", "unknown"),
                    mean=format_duration(float(entry.get("MeanNanoseconds", 0.0))),
                    category=entry.get("Category", "Unknown"),
                )
            )
        lines.append("")

    if categories:
        lines.append("## Category coverage")
        lines.append("")
        for category, count in sorted(categories.items()):
            lines.append(f"- **{category}**: {count} benchmark{'s' if count != 1 else ''}")
        lines.append("")

    if slowest_entries:
        lines.append("## Slowest operations in this run")
        lines.append("")
        lines.append("| Benchmark | Mean | Category |")
        lines.append("| --- | ---: | --- |")
        for entry in slowest_entries:
            lines.append(
                "| {benchmark} | {mean} | {category} |".format(
                    benchmark=entry.get("Benchmark", "unknown"),
                    mean=format_duration(float(entry.get("MeanNanoseconds", 0.0))),
                    category=entry.get("Category", "Unknown"),
                )
            )
        lines.append("")

    lines.append("## Artifact contents")
    lines.append("")
    lines.append("- `summary.md` - canonical markdown summary emitted by the benchmark runner")
    lines.append("- `summary.json` - machine-readable benchmark metadata and measurements")
    lines.append("- `github-report.md` - GitHub-focused headline report for this run")
    lines.append("- `benchmarkdotnet-results/` - raw BenchmarkDotNet CSV, HTML, and GitHub markdown reports when available")
    lines.append("- `logs/` - BenchmarkDotNet execution logs when available")
    lines.append("")

    if summary_markdown_path.is_file():
        lines.append("<details>")
        lines.append("<summary>Full canonical benchmark summary</summary>")
        lines.append("")
        lines.append(summary_markdown_path.read_text(encoding="utf-8").rstrip())
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def append_run_context(lines: list[str]) -> None:
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    ref_name = os.environ.get("GITHUB_REF_NAME")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    run_number = os.environ.get("GITHUB_RUN_NUMBER")
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")

    if repository and run_id and run_number:
        run_url = f"{server_url}/{repository}/actions/runs/{run_id}"
        description = f"[{repository} run #{run_number}]({run_url})"
        if ref_name:
            description += f" on `{ref_name}`"
        if event_name:
            description += f" via `{event_name}`"
        lines.append(f"- Workflow run: {description}")
    elif ref_name or event_name:
        details = []
        if ref_name:
            details.append(f"ref `{ref_name}`")
        if event_name:
            details.append(f"event `{event_name}`")
        lines.append(f"- Workflow context: {' / '.join(details)}")


def format_generated_utc(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return value

    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")


def format_duration(nanoseconds: float) -> str:
    if nanoseconds >= 1_000_000:
        return f"{nanoseconds / 1_000_000:.3f}".rstrip("0").rstrip(".") + " ms"
    if nanoseconds >= 1_000:
        return f"{nanoseconds / 1_000:.3f}".rstrip("0").rstrip(".") + " μs"
    return f"{nanoseconds:.3f}".rstrip("0").rstrip(".") + " ns"


if __name__ == "__main__":
    raise SystemExit(main())
