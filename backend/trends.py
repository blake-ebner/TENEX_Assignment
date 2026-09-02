# ---------------------------------------------------------------------------
# trends.py
# Aggregates findings across every analysis a user has run.
#
# A single anomaly is an incident. The same user flagged in six consecutive
# uploads is a pattern — and nothing in a per-file report can show that, because
# each report only ever sees one file. This module is the cross-file view.
#
# Deliberately a pure function over plain dicts: no database, no ORM, no
# network. That keeps the interesting logic testable without Postgres.
# ---------------------------------------------------------------------------


def _confidence(anomaly: dict) -> float:
    """Anomaly confidence as a float, tolerating missing or junk values."""
    try:
        return float(anomaly.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def build_trends(reports: list[dict]) -> dict:
    """
    Rolls a list of completed reports up into cross-upload patterns.

    Args:
        reports: Completed reports in chronological order (oldest first), each
                 a dict with upload_id, filename, created_at, risk_level and
                 anomalies. Anomalies may carry attack_techniques.

    Returns:
        A dict with:
          report_count         - how many reports were rolled up
          reports              - per-report summary, chronological
          flagged_users        - every user ever flagged, worst offenders first
          recurring_techniques - ATT&CK techniques seen, most persistent first

        `report_count` on a user or technique is what matters: appearing in many
        separate reports is a stronger signal than many hits in a single file,
        which one noisy afternoon can produce.
    """
    users: dict[str, dict] = {}
    techniques: dict[str, dict] = {}
    per_report = []

    for report in reports:
        filename = report.get("filename") or "(unknown)"
        created = str(report.get("created_at") or "")
        anomalies = report.get("anomalies") or []

        per_report.append({
            "upload_id": str(report.get("upload_id") or ""),
            "filename": filename,
            "created_at": created,
            "risk_level": report.get("risk_level") or "Low",
            "anomaly_count": len(anomalies),
        })

        # Tracked per report so one file with ten hits for a user still counts
        # as a single report appearance.
        users_this_report: set[str] = set()
        techniques_this_report: set[str] = set()

        for anomaly in anomalies:
            user = (anomaly.get("user") or "unknown").strip() or "unknown"
            entry = users.setdefault(user, {
                "user": user,
                "report_count": 0,
                "anomaly_count": 0,
                "max_confidence": 0.0,
                "first_seen": created,
                "last_seen": created,
                "filenames": [],
            })
            entry["anomaly_count"] += 1
            entry["max_confidence"] = max(entry["max_confidence"], _confidence(anomaly))
            entry["last_seen"] = created
            if user not in users_this_report:
                users_this_report.add(user)
                entry["report_count"] += 1
                if filename not in entry["filenames"]:
                    entry["filenames"].append(filename)

            for technique in anomaly.get("attack_techniques") or []:
                tid = (technique.get("id") or "").strip()
                if not tid:
                    continue
                tentry = techniques.setdefault(tid, {
                    "id": tid,
                    "name": technique.get("name") or "",
                    "report_count": 0,
                    "anomaly_count": 0,
                })
                tentry["anomaly_count"] += 1
                # Keep the first non-empty name we see for this ID
                if not tentry["name"] and technique.get("name"):
                    tentry["name"] = technique["name"]
                if tid not in techniques_this_report:
                    techniques_this_report.add(tid)
                    tentry["report_count"] += 1

    # Most persistent first, then most active, then alphabetical so the order is
    # stable across identical inputs.
    flagged_users = sorted(
        users.values(),
        key=lambda u: (-u["report_count"], -u["anomaly_count"], u["user"]),
    )
    recurring_techniques = sorted(
        techniques.values(),
        key=lambda t: (-t["report_count"], -t["anomaly_count"], t["id"]),
    )

    for user in flagged_users:
        user["max_confidence"] = round(user["max_confidence"], 2)

    return {
        "report_count": len(reports),
        "reports": per_report,
        "flagged_users": flagged_users,
        "recurring_techniques": recurring_techniques,
    }
