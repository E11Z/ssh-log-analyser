"""Render detector results as a terminal table, JSON or CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from analyser.detector import IpReport

TABLE_HEADERS = ["IP", "Total", "Peak/window", "Flagged", "First seen", "Last seen", "Top usernames"]
CSV_FIELDS = [
    "ip", "total_failures", "peak_in_window", "peak_window_start",
    "first_seen", "last_seen", "flagged", "usernames",
]


def top_usernames(report: IpReport, limit: int = 3) -> str:
    shown = [f"{name or '<empty>'}({count})" for name, count in report.usernames.most_common(limit)]
    extra = len(report.usernames) - limit
    if extra > 0:
        shown.append(f"+{extra} more")
    return ", ".join(shown)


def table_row(report: IpReport) -> list[str]:
    return [
        report.ip,
        str(report.total_failures),
        str(report.peak_in_window),
        "YES" if report.flagged else "no",
        f"{report.first_seen:%Y-%m-%d %H:%M:%S}",
        f"{report.last_seen:%Y-%m-%d %H:%M:%S}",
        top_usernames(report),
    ]


def format_table(reports: list[IpReport], top: int) -> str:
    rows = [TABLE_HEADERS] + [table_row(r) for r in reports[:top]]
    widths = [max(len(row[i]) for row in rows) for i in range(len(TABLE_HEADERS))]
    lines = ["  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip() for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def to_dict(report: IpReport) -> dict[str, Any]:
    return {
        "ip": report.ip,
        "total_failures": report.total_failures,
        "peak_in_window": report.peak_in_window,
        "peak_window_start": report.peak_window_start.isoformat(),
        "first_seen": report.first_seen.isoformat(),
        "last_seen": report.last_seen.isoformat(),
        "flagged": report.flagged,
        "usernames": dict(report.usernames.most_common()),
    }


def write_json(reports: list[IpReport], path: Path, settings: dict[str, Any]) -> None:
    # Settings are stored alongside results so a saved file explains how it was produced.
    payload = {"settings": settings, "results": [to_dict(r) for r in reports]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_csv(reports: list[IpReport], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for report in reports:
            row = to_dict(report)
            # One row per IP keeps the CSV easy to sort in a spreadsheet.
            row["usernames"] = ";".join(f"{name}:{count}" for name, count in row["usernames"].items())
            writer.writerow(row)
