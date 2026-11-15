import csv
import json
from collections import Counter
from datetime import datetime

from analyser.detector import IpReport
from analyser.report import format_table, top_usernames, write_csv, write_json

T = datetime(2026, 11, 15, 3, 0, 0)


def make_report(ip: str, flagged: bool, usernames: dict[str, int]) -> IpReport:
    total = sum(usernames.values())
    return IpReport(ip, total, total, T, T, T, Counter(usernames), flagged)


REPORTS = [
    make_report("203.0.113.9", True, {"root": 5, "admin": 3}),
    make_report("192.0.2.1", False, {"alice_demo": 1}),
]


def test_table_has_header_and_rows():
    lines = format_table(REPORTS, top=10).splitlines()
    assert lines[0].startswith("IP")
    assert set(lines[1].replace(" ", "")) == {"-"}
    assert "203.0.113.9" in lines[2] and "YES" in lines[2]
    assert "192.0.2.1" in lines[3] and "no" in lines[3]


def test_table_respects_top():
    lines = format_table(REPORTS, top=1).splitlines()
    assert len(lines) == 3
    assert "192.0.2.1" not in "\n".join(lines)


def test_top_usernames_truncates():
    report = make_report("192.0.2.1", True, {"a": 4, "b": 3, "c": 2, "d": 1, "e": 1})
    assert top_usernames(report) == "a(4), b(3), c(2), +2 more"


def test_json_round_trip(tmp_path):
    path = tmp_path / "out.json"
    write_json(REPORTS, path, {"threshold": 5, "window_seconds": 300})
    data = json.loads(path.read_text())
    assert data["settings"] == {"threshold": 5, "window_seconds": 300}
    assert data["results"][0]["ip"] == "203.0.113.9"
    assert data["results"][0]["usernames"] == {"root": 5, "admin": 3}
    assert data["results"][0]["first_seen"] == "2026-11-15T03:00:00"


def test_csv_columns_and_rows(tmp_path):
    path = tmp_path / "out.csv"
    write_csv(REPORTS, path)
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["ip"] == "203.0.113.9"
    assert rows[0]["flagged"] == "True"
    assert rows[0]["usernames"] == "root:5;admin:3"
