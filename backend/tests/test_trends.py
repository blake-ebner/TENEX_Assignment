# ---------------------------------------------------------------------------
# tests/test_trends.py
# Tests for the cross-upload trend aggregation.
#
# Run from the backend/ directory:
#     pytest
# ---------------------------------------------------------------------------

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trends import build_trends  # noqa: E402


def anomaly(user, confidence=0.8, techniques=()):
    return {
        "user": user,
        "confidence": confidence,
        "attack_techniques": [{"id": t[0], "name": t[1]} for t in techniques],
    }


def report(name, when, *anomalies, risk="High"):
    return {
        "upload_id": f"id-{name}",
        "filename": name,
        "created_at": when,
        "risk_level": risk,
        "anomalies": list(anomalies),
    }


# ---------------------------------------------------------------------------
# Shape and empty cases
# ---------------------------------------------------------------------------

def test_no_reports_yields_empty_trends():
    t = build_trends([])

    assert t["report_count"] == 0
    assert t["reports"] == []
    assert t["flagged_users"] == []
    assert t["recurring_techniques"] == []


def test_reports_with_no_anomalies_still_counted():
    t = build_trends([report("clean.log", "2024-01-01", risk="Low")])

    assert t["report_count"] == 1
    assert t["reports"][0]["anomaly_count"] == 0
    assert t["flagged_users"] == []


# ---------------------------------------------------------------------------
# Repeat offenders — the point of the feature
# ---------------------------------------------------------------------------

def test_user_flagged_across_weeks_outranks_a_one_day_spike():
    """
    The whole reason this view exists: 'jsmith flagged three weeks running' is a
    stronger signal than 'bob had five hits in one bad afternoon'.
    """
    reports = [
        report("wk1.log", "2024-01-01", anomaly("jsmith"), *[anomaly("bob")] * 5),
        report("wk2.log", "2024-01-08", anomaly("jsmith")),
        report("wk3.log", "2024-01-15", anomaly("jsmith")),
    ]

    users = build_trends(reports)["flagged_users"]

    assert users[0]["user"] == "jsmith"
    assert users[0]["report_count"] == 3
    assert users[1]["user"] == "bob"
    assert users[1]["report_count"] == 1
    assert users[1]["anomaly_count"] == 5   # more hits, but only one report


def test_many_hits_in_one_report_count_as_one_appearance():
    reports = [report("a.log", "2024-01-01", *[anomaly("jsmith")] * 4)]

    user = build_trends(reports)["flagged_users"][0]

    assert user["report_count"] == 1
    assert user["anomaly_count"] == 4


def test_first_and_last_seen_span_the_reports():
    reports = [
        report("a.log", "2024-01-01", anomaly("jsmith")),
        report("b.log", "2024-02-01", anomaly("jsmith")),
    ]

    user = build_trends(reports)["flagged_users"][0]

    assert user["first_seen"] == "2024-01-01"
    assert user["last_seen"] == "2024-02-01"
    assert user["filenames"] == ["a.log", "b.log"]


def test_max_confidence_is_the_highest_seen():
    reports = [
        report("a.log", "2024-01-01", anomaly("jsmith", 0.4)),
        report("b.log", "2024-01-02", anomaly("jsmith", 0.93)),
        report("c.log", "2024-01-03", anomaly("jsmith", 0.6)),
    ]

    assert build_trends(reports)["flagged_users"][0]["max_confidence"] == 0.93


def test_missing_or_junk_confidence_does_not_crash():
    reports = [report("a.log", "2024-01-01",
                      {"user": "jsmith"},
                      {"user": "jsmith", "confidence": None},
                      {"user": "jsmith", "confidence": "high"})]

    assert build_trends(reports)["flagged_users"][0]["max_confidence"] == 0.0


def test_missing_user_is_bucketed_not_dropped():
    reports = [report("a.log", "2024-01-01", {"confidence": 0.9}, {"user": "  "})]

    users = build_trends(reports)["flagged_users"]

    assert len(users) == 1
    assert users[0]["user"] == "unknown"
    assert users[0]["anomaly_count"] == 2


# ---------------------------------------------------------------------------
# Recurring ATT&CK techniques
# ---------------------------------------------------------------------------

def test_techniques_ranked_by_how_many_reports_they_appear_in():
    c2 = ("T1071.001", "Web Protocols")
    exfil = ("T1041", "Exfiltration Over C2 Channel")
    reports = [
        report("a.log", "2024-01-01", anomaly("u1", techniques=[c2, exfil])),
        report("b.log", "2024-01-08", anomaly("u2", techniques=[c2])),
        report("c.log", "2024-01-15", anomaly("u3", techniques=[c2])),
    ]

    techniques = build_trends(reports)["recurring_techniques"]

    assert [t["id"] for t in techniques] == ["T1071.001", "T1041"]
    assert techniques[0]["report_count"] == 3
    assert techniques[0]["name"] == "Web Protocols"
    assert techniques[1]["report_count"] == 1


def test_same_technique_twice_in_one_report_is_one_appearance():
    c2 = ("T1071.001", "Web Protocols")
    reports = [report("a.log", "2024-01-01",
                      anomaly("u1", techniques=[c2]),
                      anomaly("u2", techniques=[c2]))]

    technique = build_trends(reports)["recurring_techniques"][0]

    assert technique["report_count"] == 1
    assert technique["anomaly_count"] == 2


def test_techniques_without_an_id_are_ignored():
    reports = [report("a.log", "2024-01-01",
                      {"user": "u1", "confidence": 0.8,
                       "attack_techniques": [{"id": "", "name": "Nameless"},
                                             {"name": "No id at all"}]})]

    assert build_trends(reports)["recurring_techniques"] == []


def test_anomalies_without_techniques_are_fine():
    """Older reports predate ATT&CK mapping and have no such key."""
    reports = [report("a.log", "2024-01-01", {"user": "u1", "confidence": 0.8})]

    t = build_trends(reports)
    assert t["recurring_techniques"] == []
    assert t["flagged_users"][0]["user"] == "u1"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_equal_ranking_falls_back_to_alphabetical():
    """Identical input must produce identical output ordering."""
    reports = [report("a.log", "2024-01-01",
                      anomaly("zoe"), anomaly("adam"), anomaly("mike"))]

    users = [u["user"] for u in build_trends(reports)["flagged_users"]]

    assert users == ["adam", "mike", "zoe"]
