"""Generate a fake auth.log for demos and tests.

Every IP comes from ranges reserved for documentation (RFC 5737 / RFC 3849),
so nothing in the output can point at a real host. Usernames are made up or
generic names that bots commonly try.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "lab-vm"
START = datetime(2026, 11, 15, 2, 0, 0)

LEGIT_USERS = {"alice_demo": "198.51.100.5", "bob_demo": "198.51.100.6"}
BOT_USERNAMES = ["root", "admin", "test", "oracle", "ubuntu", "pi", "guest", "postgres", "ftpuser", "test_user"]

FAST_ATTACKER = "203.0.113.66"
SLOW_ATTACKER = "203.0.113.200"
IPV6_ATTACKER = "2001:db8::bad"
TYPO_USER = ("alice_demo", "198.51.100.5")


def stamp(when: datetime) -> str:
    # Syslog pads single-digit days with a space ("Nov  5"), not a zero.
    return f"{when:%b} {when.day:>2} {when:%H:%M:%S}"


def sshd(when: datetime, pid: int, msg: str) -> tuple[datetime, str]:
    return when, f"{stamp(when)} {HOST} sshd[{pid}]: {msg}"


def failed(when: datetime, pid: int, user: str, ip: str, port: int, valid: bool) -> list[tuple[datetime, str]]:
    if valid:
        return [sshd(when, pid, f"Failed password for {user} from {ip} port {port} ssh2")]
    # Real sshd logs both lines for an unknown user; the parser must not double count.
    return [
        sshd(when, pid, f"Invalid user {user} from {ip} port {port}"),
        sshd(when, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2"),
    ]


def is_valid(user: str) -> bool:
    return user in {"root", *LEGIT_USERS}


def attack(rng: random.Random, ip: str, start: datetime, count: int, gap: tuple[int, int]) -> list[tuple[datetime, str]]:
    events, when = [], start
    for _ in range(count):
        user = rng.choice(BOT_USERNAMES)
        events += failed(when, rng.randint(2000, 9000), user, ip, rng.randint(30000, 60000), is_valid(user))
        when += timedelta(seconds=rng.randint(*gap))
    return events


def normal_logins(rng: random.Random) -> list[tuple[datetime, str]]:
    events = []
    for hour in range(6):
        for user, ip in LEGIT_USERS.items():
            when = START + timedelta(hours=hour, minutes=rng.randint(0, 59))
            events.append(sshd(when, rng.randint(1000, 1999),
                               f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 50000)} ssh2"))
    return events


def typo_logins(rng: random.Random) -> list[tuple[datetime, str]]:
    user, ip = TYPO_USER
    when = START + timedelta(hours=1, minutes=15)
    events = failed(when, 1500, user, ip, 41000, True) + failed(when + timedelta(seconds=6), 1501, user, ip, 41001, True)
    events.append(sshd(when + timedelta(seconds=14), 1502, f"Accepted password for {user} from {ip} port 41002 ssh2"))
    return events


def noise(rng: random.Random) -> list[tuple[datetime, str]]:
    events = []
    for minute in range(0, 360, 17):
        when = START + timedelta(minutes=minute)
        events.append((when, f"{stamp(when)} {HOST} CRON[{rng.randint(100, 999)}]: "
                             "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
    when = START + timedelta(minutes=5)
    events.append((when, f"{stamp(when)} {HOST} systemd-logind[400]: New session 12 of user alice_demo."))
    return events


def generate(seed: int = 1337) -> list[str]:
    rng = random.Random(seed)
    events = (
        normal_logins(rng)
        + typo_logins(rng)
        + noise(rng)
        # About 40 attempts in roughly 2 minutes: the classic noisy bot.
        + attack(rng, FAST_ATTACKER, START + timedelta(hours=2), 40, (1, 5))
        # One attempt every 3-6 minutes for hours: lots in total, never a burst.
        + attack(rng, SLOW_ATTACKER, START + timedelta(minutes=10), 60, (180, 360))
        + attack(rng, IPV6_ATTACKER, START + timedelta(hours=4), 15, (2, 8))
    )
    # Stable sort keeps each "Invalid user" line before its matching "Failed" line.
    events.sort(key=lambda event: event[0])
    return [line for _, line in events]


def main() -> None:
    parser = argparse.ArgumentParser(description="Write a fake auth.log sample.")
    parser.add_argument("--out", type=Path, default=Path("samples/auth_sample.log"))
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(generate(args.seed)) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
