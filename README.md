# SSH Log Analyser

Reads a Linux SSH auth log and flags source IPs that fail to log in too many times in a short window. This is the pattern a password-guessing (brute-force) bot leaves behind.

## How it works
1. **Read the file line by line.** Only `sshd` lines are looked at. Everything else (CRON, systemd, and so on) is skipped and counted.
2. **Pick out failed logins.** A regex matches `Failed password`, `Failed publickey` and `Failed keyboard-interactive/pam` lines and pulls out the time, the username, the source IP, and whether sshd said the user doesn't exist.
3. **Group by IP.** All failures from the same source IP are put together and sorted by time.
4. **Slide a window over each IP's failures.** For every IP the tool finds the busiest stretch of `--window` seconds. If that stretch holds **more than** `--threshold` failures, the IP is flagged.
5. **Report.** A table shows the worst IPs first, with the usernames they tried. You can also save the full results as JSON and/or CSV.

### Design choices
- **Standard library only.** The tool needs nothing beyond Python, so it runs on any lab VM. pytest is only needed for the tests.
- **Peak in a window, not total count.** An IP that fails 60 times over 5 hours is a different thing from one that fails 40 times in 2 minutes. Counting the total alone would flag both, or neither, depending on the number you picked. Looking at the busiest window separates them. The sample log has both so you can see the difference.
- **Two pointers instead of re-counting.** The window check moves a start pointer and an end pointer forward through the sorted times. Each failure is visited about twice, so an IP with 50,000 attempts is still fast.
- **No double counting.** For an unknown user, sshd writes `Invalid user bob from ...` *and* `Failed password for invalid user bob from ...` for the same attempt. Only the `Failed ...` line is counted.
- **Two timestamp formats.** Older systems write `Nov 15 03:12:45`, which has no year. Newer Ubuntu and Debian write ISO 8601 (`2026-11-15T03:12:45+00:00`). Both work. For the old format you can set `--year`. If the month goes backwards (December to January), the year is bumped automatically.
- **Bad lines never crash the tool.** Attackers control the username field, so lines can be odd or contain broken bytes. Anything that doesn't match is skipped, invalid UTF-8 is replaced, and IPs are checked with `ipaddress`.
- **Exit codes for scripting.** `0` means nothing was flagged, `1` means at least one IP was flagged, and `2` means bad input. That makes it easy to use from cron or CI.
- **Safe sample data.** `scripts/generate_sample.py` builds the sample with a fixed seed. All of its IPs come from ranges reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), so none of them can be a real host. A test checks this.

### Project layout
```
main.py                     command-line entry point
analyser/parser.py          log lines -> FailedLogin records
analyser/detector.py        grouping and sliding-window detection
analyser/report.py          table, JSON and CSV output
scripts/generate_sample.py  builds samples/auth_sample.log
tests/                      pytest tests
```

## Install
    git clone <repo-url>
    cd ssh-log-analyser
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt

## Usage
    python main.py --help

    # Analyse the bundled fake log with the defaults (more than 5 failures in 300 s)
    python main.py samples/auth_sample.log --year 2026

    # Stricter rule, show 5 rows, export both formats
    python main.py samples/auth_sample.log --year 2026 --threshold 10 --window 60 --top 5 \
        --json results.json --csv results.csv

    # On your own lab VM (reading auth.log usually needs sudo)
    sudo python main.py /var/log/auth.log

    # Rebuild the sample log
    python scripts/generate_sample.py

## Example output
Real run against the bundled sample:

```
$ python main.py samples/auth_sample.log --year 2026 --json results.json --csv results.csv
Parsed 117 failed logins from 4 IPs (136 other lines skipped).
Rule: more than 5 failures within 300s. Flagged IPs: 2.

IP             Total  Peak/window  Flagged  First seen           Last seen            Top usernames
-------------  -----  -----------  -------  -------------------  -------------------  ---------------------------------------
203.0.113.66   40     40           YES      2026-11-15 04:00:00  2026-11-15 04:02:05  ftpuser(6), root(5), oracle(5), +7 more
2001:db8::bad  15     15           YES      2026-11-15 06:00:00  2026-11-15 06:01:13  pi(2), test_user(2), ubuntu(2), +6 more
203.0.113.200  60     2            no       2026-11-15 02:10:00  2026-11-15 06:44:07  root(8), test(7), pi(7), +7 more
198.51.100.5   2      2            no       2026-11-15 03:15:00  2026-11-15 03:15:06  alice_demo(2)

Wrote results.json
Wrote results.csv
$ echo $?
1
```

`203.0.113.200` has the most failures in total but isn't flagged, because it never makes more than 2 attempts in any 5-minute window. That's the "low and slow" case, covered under Limitations.

## Tests
    pytest

There are 29 tests:
- the parser: each line type, both timestamp formats, the year rollover, IPv6, junk lines
- the detector: exactly at the threshold vs one over, the window edge, ordering
- JSON and CSV export
- the CLI and its exit codes
- an end-to-end check that the committed sample matches the generator and only uses documentation IPs

## What I learned
- sshd logs one bad attempt for an unknown user as two lines, so a naive `grep Failed` + `grep Invalid` count is wrong.
- Classic syslog timestamps have no year or timezone. Any time-window logic has to guess the year and deal with December to January.
- A sliding window with two pointers turns "how many events in any N seconds" from O(n²) into O(n).
- Thresholds are a trade-off. A low threshold catches more but flags people who mistype their password. A long window catches slower bots but is noisier.
- Logs contain attacker-controlled text, so a parser should expect garbage and never trust a field just because it matched a regex.

## Limitations
- "Low and slow" attackers that stay under the threshold aren't flagged. Look at the Total column, or use a longer `--window`.
- Many IPs working together (a botnet), each with only a few attempts, won't be caught per IP.
- Syslog timestamps have no timezone. ISO timestamps have their offset dropped, so a file mixing both formats from different zones may be off.
- It doesn't read the binary journald format or rotated `.gz` files. For journald, export to text first: `journalctl -u ssh > ssh.txt`.
- It only reports. It doesn't block IPs (that's what tools like fail2ban are for).

## Disclaimer
For educational use on systems you own or have permission to test.
