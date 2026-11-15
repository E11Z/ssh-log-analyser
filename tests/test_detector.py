from datetime import datetime, timedelta

from analyser.detector import detect, peak_window
from analyser.parser import FailedLogin

START = datetime(2026, 11, 15, 3, 0, 0)


def failures(ip: str, count: int, gap_seconds: int, users: list[str] | None = None) -> list[FailedLogin]:
    users = users or ["root"]
    return [
        FailedLogin(START + timedelta(seconds=i * gap_seconds), ip, users[i % len(users)], False)
        for i in range(count)
    ]


def test_exactly_threshold_is_not_flagged():
    [report] = detect(failures("192.0.2.1", 5, 1), threshold=5, window_seconds=60)
    assert report.peak_in_window == 5
    assert report.flagged is False


def test_one_over_threshold_is_flagged():
    [report] = detect(failures("192.0.2.1", 6, 1), threshold=5, window_seconds=60)
    assert report.flagged is True


def test_spread_out_failures_are_not_flagged():
    # 20 failures, one every 2 minutes: lots in total, never more than 1 per minute.
    [report] = detect(failures("192.0.2.1", 20, 120), threshold=5, window_seconds=60)
    assert report.total_failures == 20
    assert report.peak_in_window == 1
    assert report.flagged is False


def test_window_edge_is_inclusive():
    times = [START, START + timedelta(seconds=60)]
    assert peak_window(times, timedelta(seconds=60)) == (2, START)
    assert peak_window(times, timedelta(seconds=59)) == (1, START)


def test_peak_window_finds_burst_in_middle():
    times = [START, START + timedelta(hours=1)] + [START + timedelta(hours=2, seconds=i) for i in range(4)]
    count, start = peak_window(times, timedelta(seconds=10))
    assert count == 4
    assert start == START + timedelta(hours=2)


def test_multiple_ips_sorted_worst_first():
    data = failures("192.0.2.1", 3, 1) + failures("203.0.113.9", 10, 1) + failures("198.51.100.2", 7, 1)
    reports = detect(data, threshold=5, window_seconds=60)
    assert [r.ip for r in reports] == ["203.0.113.9", "198.51.100.2", "192.0.2.1"]
    assert [r.flagged for r in reports] == [True, True, False]


def test_usernames_counted_and_seen_times():
    data = failures("192.0.2.1", 4, 10, users=["admin", "root"])
    [report] = detect(reversed(data), threshold=5, window_seconds=60)
    assert report.usernames == {"admin": 2, "root": 2}
    assert report.first_seen == START
    assert report.last_seen == START + timedelta(seconds=30)


def test_empty_input():
    assert detect([], threshold=5, window_seconds=60) == []
