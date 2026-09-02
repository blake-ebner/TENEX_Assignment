# ---------------------------------------------------------------------------
# tests/test_parser.py
# Tests for the ZScaler log parser and event-selection logic.
#
# Run from the backend/ directory:
#     pytest
# ---------------------------------------------------------------------------

import sys
from pathlib import Path

import pytest

# The backend runs with its own directory on the path (see Dockerfile), so
# tests need the same for `import parser` to resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import (  # noqa: E402
    FIELD_NAMES,
    get_summary_stats,
    parse_log_file,
    score_event,
    select_significant_events,
)

# A routine, uninteresting request — the baseline every test line starts from
BASELINE = {
    "timestamp": "2024-01-17 08:00:00",
    "action": "ALLOW",
    "login": "jdoe@acme.com",
    "dept": "Engineering",
    "cip": "10.1.2.100",
    "sip": "203.45.12.88",
    "srv_dport": "443",
    "proto": "HTTPS",
    "url": "https://www.google.com/",
    "urlcat": "Search Engines",
    "urlsupercat": "Web",
    "urlclass": "Productivity",
    "bytes_sent": "512",
    "bytes_received": "4096",
    "riskscore": "3",
    "threatseverity": "None",
    "threatname": "None",
    "malwarecat": "None",
    "malwareclass": "None",
    "srcip_country": "US",
    "dstip_country": "US",
    "is_dst_cntry_risky": "No",
    "srvtlsversion": "TLSv1.3",
    "srvcertvalidationtype": "Trusted CA",
    "is_sslselfsigned": "No",
    "is_sslexpiredca": "No",
    "bwthrottle": "No",
    "bwclassname": "HighBandwidth",
}


def line(**overrides) -> str:
    """Builds one pipe-delimited log line, overriding any baseline fields."""
    fields = {**BASELINE, **overrides}
    return "|".join(str(fields[name]) for name in FIELD_NAMES)


def write_log(tmp_path, *lines) -> str:
    """Writes lines to a temp .log file and returns its path."""
    path = tmp_path / "test.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# parse_log_file
# ---------------------------------------------------------------------------

def test_parses_a_well_formed_line(tmp_path):
    events = parse_log_file(write_log(tmp_path, line()))

    assert len(events) == 1
    assert events[0]["login"] == "jdoe@acme.com"
    assert events[0]["url"] == "https://www.google.com/"
    assert events[0]["bytes_sent"] == 512


def test_keeps_only_the_fields_we_send_to_the_ai(tmp_path):
    events = parse_log_file(write_log(tmp_path, line()))

    # sip and urlclass are parsed but deliberately dropped before the prompt
    assert "sip" not in events[0]
    assert "urlclass" not in events[0]


def test_skips_blank_comment_and_truncated_lines(tmp_path):
    path = write_log(
        tmp_path,
        "# ZScaler NSS Feed export",
        "",
        "2024-01-17 08:00:00|ALLOW|jdoe@acme.com",   # far too few fields
        line(),
        "   ",
    )

    assert len(parse_log_file(path)) == 1


def test_numeric_fields_become_integers(tmp_path):
    events = parse_log_file(write_log(tmp_path, line(bytes_sent="2048", riskscore="90")))

    assert events[0]["bytes_sent"] == 2048
    assert events[0]["bytes_received"] == 4096
    assert events[0]["riskscore"] == 90


def test_one_unparseable_number_does_not_zero_the_others(tmp_path):
    """
    Regression: a single non-numeric field used to reset all three numeric
    fields to 0, silently hiding a large transfer or a high risk score.
    """
    events = parse_log_file(
        write_log(tmp_path, line(bytes_received="-", bytes_sent="900000", riskscore="95"))
    )

    assert events[0]["bytes_received"] == 0    # the genuinely missing value
    assert events[0]["bytes_sent"] == 900000   # must survive
    assert events[0]["riskscore"] == 95        # must survive


def test_empty_file_yields_no_events(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")

    assert parse_log_file(str(path)) == []


# ---------------------------------------------------------------------------
# get_summary_stats
# ---------------------------------------------------------------------------

def test_summary_stats_of_no_events_is_empty():
    assert get_summary_stats([]) == {}


def test_summary_stats_counts_actions_users_and_bytes(tmp_path):
    path = write_log(
        tmp_path,
        line(login="a@acme.com", bytes_sent="100"),
        line(login="a@acme.com", bytes_sent="200", action="BLOCK", riskscore="80"),
        line(login="b@acme.com", bytes_sent="300"),
    )
    stats = get_summary_stats(parse_log_file(path))

    assert stats["total_events"] == 3
    assert stats["allowed"] == 2
    assert stats["blocked"] == 1
    assert stats["high_risk_events"] == 1        # riskscore 80 >= 75
    assert stats["total_bytes_sent"] == 600
    assert stats["unique_users"] == 2
    assert stats["top_users"]["a@acme.com"] == 2


def test_summary_stats_lists_risky_countries_deterministically(tmp_path):
    path = write_log(
        tmp_path,
        line(dstip_country="RU", is_dst_cntry_risky="Yes"),
        line(dstip_country="CN", is_dst_cntry_risky="Yes"),
        line(dstip_country="RU", is_dst_cntry_risky="Yes"),
        line(dstip_country="US", is_dst_cntry_risky="No"),
    )
    stats = get_summary_stats(parse_log_file(path))

    # Sorted, so identical input produces a byte-identical prompt
    assert stats["risky_countries_contacted"] == ["CN", "RU"]


# ---------------------------------------------------------------------------
# score_event
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("overrides", [
    {"riskscore": 95},
    {"action": "BLOCK"},
    {"threatname": "Emotet.Downloader"},
    {"malwarecat": "Trojan"},
    {"is_dst_cntry_risky": "Yes"},
    {"urlcat": "Malware"},
    {"threatseverity": "Critical"},
])
def test_each_threat_signal_outscores_routine_traffic(tmp_path, overrides):
    routine = parse_log_file(write_log(tmp_path, line()))[0]
    suspicious = parse_log_file(write_log(tmp_path, line(**overrides)))[0]

    assert score_event(suspicious, 10**9) > score_event(routine, 10**9)


def test_placeholder_values_are_not_treated_as_threats(tmp_path):
    """ZScaler writes 'None' and '-' for absent values, not real threat names."""
    a = parse_log_file(write_log(tmp_path, line(threatname="None", malwarecat="-")))[0]
    b = parse_log_file(write_log(tmp_path, line(threatname="", malwarecat="None")))[0]

    assert score_event(a, 10**9) == score_event(b, 10**9)


def test_large_outbound_transfer_raises_the_score(tmp_path):
    event = parse_log_file(write_log(tmp_path, line(bytes_sent="50000000")))[0]

    assert score_event(event, 10_000_000) > score_event(event, 10**12)


# ---------------------------------------------------------------------------
# select_significant_events
# ---------------------------------------------------------------------------

def test_small_files_are_sent_whole(tmp_path):
    path = write_log(tmp_path, *[line() for _ in range(10)])
    events = parse_log_file(path)

    assert select_significant_events(events, limit=150) == events


def test_selection_respects_the_limit(tmp_path):
    path = write_log(tmp_path, *[line() for _ in range(500)])
    events = parse_log_file(path)

    assert len(select_significant_events(events, limit=50)) == 50


def test_threats_late_in_a_large_file_are_still_selected(tmp_path):
    """
    The whole point of scoring: truncating to the first N events would drop a
    threat that appears at line 900 of a 1000-line file.
    """
    lines = [line(timestamp=f"2024-01-17 08:{i // 60:02d}:{i % 60:02d}") for i in range(1000)]
    lines[900] = line(
        timestamp="2024-01-17 15:00:00",
        login="victim@acme.com",
        url="http://evil.example/payload.exe",
        urlcat="Malware",
        action="BLOCK",
        riskscore="98",
        threatname="Emotet.Downloader",
        malwarecat="Trojan",
        threatseverity="Critical",
    )
    events = parse_log_file(write_log(tmp_path, *lines))

    selected = select_significant_events(events, limit=150)

    assert any(e["threatname"] == "Emotet.Downloader" for e in selected)


def test_selection_stays_in_chronological_order(tmp_path):
    # Each line gets a distinct client IP so a selected event maps back to
    # exactly one position in the file.
    lines = [line(cip=f"10.0.{i // 256}.{i % 256}", riskscore=str(i % 100))
             for i in range(400)]
    events = parse_log_file(write_log(tmp_path, *lines))
    position_of = {e["cip"]: i for i, e in enumerate(events)}

    selected = select_significant_events(events, limit=100)
    positions = [position_of[e["cip"]] for e in selected]

    assert positions == sorted(positions)
    assert len(set(positions)) == len(positions)   # no event sent twice


def test_selection_includes_some_routine_traffic(tmp_path):
    """
    A report needs a baseline: if every selected event is a threat, the AI
    cannot tell whether the file is 5% malicious or 100% malicious.
    """
    lines = [line() for _ in range(500)]
    for i in range(0, 300):
        lines[i] = line(riskscore="99", action="BLOCK", threatname="Bad.Thing")
    events = parse_log_file(write_log(tmp_path, *lines))

    selected = select_significant_events(events, limit=100)

    assert any(e["threatname"].lower() == "none" for e in selected)
