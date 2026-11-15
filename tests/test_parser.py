from datetime import datetime

from analyser.parser import parse_file, parse_lines

FAILED = "Nov 15 03:12:45 lab-vm sshd[1001]: Failed password for root from 192.0.2.10 port 50122 ssh2"
INVALID = (
    "Nov 15 03:12:46 lab-vm sshd[1002]: Failed password for invalid user test_user "
    "from 192.0.2.10 port 50123 ssh2"
)
INVALID_NOTICE = "Nov 15 03:12:46 lab-vm sshd[1002]: Invalid user test_user from 192.0.2.10 port 50123"
ACCEPTED = "Nov 15 03:13:00 lab-vm sshd[1003]: Accepted password for alice_demo from 198.51.100.5 port 4022 ssh2"
CRON = "Nov 15 03:14:01 lab-vm CRON[2000]: pam_unix(cron:session): session opened for user root"


def test_failed_password_parsed():
    result = parse_lines([FAILED], year=2026)
    assert result.skipped_lines == 0
    [failure] = result.failures
    assert failure.ip == "192.0.2.10"
    assert failure.username == "root"
    assert failure.invalid_user is False
    assert failure.timestamp == datetime(2026, 11, 15, 3, 12, 45)


def test_invalid_user_flagged_and_not_double_counted():
    result = parse_lines([INVALID_NOTICE, INVALID], year=2026)
    assert len(result.failures) == 1
    assert result.failures[0].username == "test_user"
    assert result.failures[0].invalid_user is True


def test_non_failure_lines_are_skipped():
    result = parse_lines([ACCEPTED, CRON, "garbage", ""], year=2026)
    assert result.failures == []
    assert result.skipped_lines == 4


def test_iso_timestamp_and_ipv6():
    line = (
        "2026-11-15T03:12:45.123456+00:00 lab-vm sshd[1004]: Failed password for admin "
        "from 2001:db8::42 port 50200 ssh2"
    )
    [failure] = parse_lines([line], year=1999).failures
    assert failure.ip == "2001:db8::42"
    assert failure.timestamp == datetime(2026, 11, 15, 3, 12, 45, 123456)


def test_single_digit_day_padding():
    line = "Nov  5 03:12:45 lab-vm sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"
    [failure] = parse_lines([line], year=2026).failures
    assert failure.timestamp.day == 5


def test_year_rollover():
    lines = [
        "Dec 31 23:59:58 lab-vm sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "Jan  1 00:00:02 lab-vm sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
    ]
    first, second = parse_lines(lines, year=2025).failures
    assert first.timestamp.year == 2025
    assert second.timestamp.year == 2026
    assert second.timestamp > first.timestamp


def test_publickey_failure_counted():
    line = "Nov 15 03:12:45 lab-vm sshd[1]: Failed publickey for git from 203.0.113.7 port 9 ssh2: RSA SHA256:abc"
    [failure] = parse_lines([line], year=2026).failures
    assert failure.username == "git"


def test_bad_ip_is_skipped():
    line = "Nov 15 03:12:45 lab-vm sshd[1]: Failed password for root from not-an-ip port 1 ssh2"
    result = parse_lines([line], year=2026)
    assert result.failures == []
    assert result.skipped_lines == 1


def test_parse_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(f"{FAILED}\n{CRON}\n")
    result = parse_file(log, year=2026)
    assert len(result.failures) == 1
    assert result.skipped_lines == 1
