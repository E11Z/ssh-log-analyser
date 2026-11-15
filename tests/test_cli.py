import json

import pytest

from main import EXIT_CLEAN, EXIT_ERROR, EXIT_FLAGGED, main

LINE = "Nov 15 03:12:{sec:02d} lab-vm sshd[1]: Failed password for root from 192.0.2.10 port 1 ssh2\n"


@pytest.fixture
def burst_log(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(LINE.format(sec=s) for s in range(8)))
    return log


def test_flagged_exit_code_and_exports(burst_log, tmp_path, capsys):
    out_json, out_csv = tmp_path / "r.json", tmp_path / "r.csv"
    code = main([str(burst_log), "--year", "2026", "--json", str(out_json), "--csv", str(out_csv)])
    assert code == EXIT_FLAGGED
    assert "192.0.2.10" in capsys.readouterr().out
    assert json.loads(out_json.read_text())["results"][0]["flagged"] is True
    assert out_csv.read_text().startswith("ip,")


def test_clean_exit_code_when_under_threshold(burst_log):
    assert main([str(burst_log), "--threshold", "8"]) == EXIT_CLEAN


def test_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == EXIT_ERROR
    assert "not a readable file" in capsys.readouterr().err


def test_rejects_zero_threshold(burst_log):
    with pytest.raises(SystemExit) as exc:
        main([str(burst_log), "--threshold", "0"])
    assert exc.value.code == 2
