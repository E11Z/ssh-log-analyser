"""Group failures by source IP and flag brute-force bursts."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from analyser.parser import FailedLogin


@dataclass
class IpReport:
    ip: str
    total_failures: int
    peak_in_window: int
    peak_window_start: datetime
    first_seen: datetime
    last_seen: datetime
    usernames: Counter[str]
    flagged: bool


def group_by_ip(failures: Iterable[FailedLogin]) -> dict[str, list[FailedLogin]]:
    groups: dict[str, list[FailedLogin]] = defaultdict(list)
    for failure in failures:
        groups[failure.ip].append(failure)
    return groups


def peak_window(times: list[datetime], window: timedelta) -> tuple[int, datetime]:
    """Return the most failures that fit in any `window`, and where that window starts.

    Two pointers over sorted times: O(n) instead of re-counting per window, which
    matters for IPs with tens of thousands of attempts.
    """
    best_count, best_start = 0, times[0]
    start = 0
    for end, current in enumerate(times):
        # Inclusive window: attempts exactly `window` apart still count together.
        while current - times[start] > window:
            start += 1
        if end - start + 1 > best_count:
            best_count, best_start = end - start + 1, times[start]
    return best_count, best_start


def build_report(ip: str, failures: list[FailedLogin], threshold: int, window: timedelta) -> IpReport:
    times = sorted(f.timestamp for f in failures)
    peak, peak_start = peak_window(times, window)
    return IpReport(
        ip=ip,
        total_failures=len(times),
        peak_in_window=peak,
        peak_window_start=peak_start,
        first_seen=times[0],
        last_seen=times[-1],
        usernames=Counter(f.username for f in failures),
        flagged=peak > threshold,
    )


def detect(failures: Iterable[FailedLogin], threshold: int, window_seconds: int) -> list[IpReport]:
    """Report every IP, worst first. An IP is flagged with MORE than `threshold` in the window."""
    window = timedelta(seconds=window_seconds)
    reports = [build_report(ip, group, threshold, window) for ip, group in group_by_ip(failures).items()]
    return sorted(reports, key=lambda r: (r.flagged, r.peak_in_window, r.total_failures), reverse=True)
