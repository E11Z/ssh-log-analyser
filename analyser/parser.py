"""Turn raw auth.log lines into FailedLogin records."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

# Classic syslog: "Nov 15 03:12:45 host sshd[123]: message"
SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
# Newer rsyslog defaults (Ubuntu 24.04+, Debian 12+) use ISO 8601 timestamps.
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
# Only "Failed <method>" lines are counted. sshd also logs "Invalid user X from Y"
# for the same attempt, so counting that too would double every invalid-user try.
FAILED_MSG = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+"
)


@dataclass(frozen=True)
class FailedLogin:
    timestamp: datetime
    ip: str
    username: str
    invalid_user: bool


@dataclass
class ParseResult:
    failures: list[FailedLogin]
    skipped_lines: int


def parse_iso_timestamp(text: str) -> datetime:
    # Drop the offset so ISO and syslog times compare as the same naive local-ish type.
    return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)


def parse_syslog_timestamp(text: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def parse_message(msg: str, timestamp: datetime) -> FailedLogin | None:
    match = FAILED_MSG.match(msg)
    if not match:
        return None
    ip = match["ip"]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    return FailedLogin(timestamp, ip, match["user"], bool(match["invalid"]))


def parse_lines(lines: Iterable[str], year: int) -> ParseResult:
    """Parse lines, counting the ones that are not sshd failures as skipped.

    Syslog timestamps carry no year, so `year` is used for the first line and
    bumped whenever the month jumps backwards (a Dec -> Jan rollover).
    """
    failures: list[FailedLogin] = []
    skipped = 0
    last_syslog: datetime | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        timestamp = None
        msg = ""
        if match := ISO_LINE.match(line):
            timestamp, msg = parse_iso_timestamp(match["ts"]), match["msg"]
        elif match := SYSLOG_LINE.match(line):
            timestamp = parse_syslog_timestamp(match["ts"], year)
            if last_syslog and timestamp.month < last_syslog.month:
                year += 1
                timestamp = timestamp.replace(year=year)
            last_syslog = timestamp
            msg = match["msg"]
        failure = parse_message(msg, timestamp) if timestamp else None
        if failure:
            failures.append(failure)
        else:
            skipped += 1
    return ParseResult(failures, skipped)


def read_lines(path: Path) -> Iterator[str]:
    # errors="replace" because attackers can put arbitrary bytes in usernames.
    with path.open(encoding="utf-8", errors="replace") as handle:
        yield from handle


def parse_file(path: Path, year: int) -> ParseResult:
    return parse_lines(read_lines(path), year)
