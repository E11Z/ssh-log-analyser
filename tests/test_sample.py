"""End-to-end checks against the committed, generated sample log."""

import ipaddress
from pathlib import Path

from analyser.detector import detect
from analyser.parser import parse_file
from scripts.generate_sample import FAST_ATTACKER, IPV6_ATTACKER, SLOW_ATTACKER, generate

SAMPLE = Path(__file__).parent.parent / "samples" / "auth_sample.log"
DOC_RANGES = [ipaddress.ip_network(n) for n in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def test_committed_sample_matches_generator():
    assert SAMPLE.read_text().splitlines() == generate()


def test_sample_uses_only_documentation_ips():
    for failure in parse_file(SAMPLE, 2026).failures:
        assert any(ipaddress.ip_address(failure.ip) in net for net in DOC_RANGES)


def test_sample_detection():
    reports = {r.ip: r for r in detect(parse_file(SAMPLE, 2026).failures, threshold=5, window_seconds=300)}
    assert reports[FAST_ATTACKER].flagged
    assert reports[IPV6_ATTACKER].flagged
    assert not reports[SLOW_ATTACKER].flagged
    assert reports[SLOW_ATTACKER].total_failures == 60
    assert not reports["198.51.100.5"].flagged
