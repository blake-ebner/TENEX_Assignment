# ---------------------------------------------------------------------------
# parser.py
# Parses ZScaler web proxy log files into structured Python dicts.
# Also computes summary statistics used by the AI analysis step.
# ---------------------------------------------------------------------------

from datetime import datetime

# ---------------------------------------------------------------------------
# All field names in the order they appear in each pipe-delimited log line.
# This list is used to map raw column positions to human-readable keys.
# ---------------------------------------------------------------------------
FIELD_NAMES = [
    "timestamp", "action", "login", "dept", "cip", "sip",
    "srv_dport", "proto", "url", "urlcat", "urlsupercat", "urlclass",
    "bytes_sent", "bytes_received", "riskscore", "threatseverity",
    "threatname", "malwarecat", "malwareclass", "srcip_country",
    "dstip_country", "is_dst_cntry_risky", "srvtlsversion",
    "srvcertvalidationtype", "is_sslselfsigned", "is_sslexpiredca",
    "bwthrottle", "bwclassname"
]

# ---------------------------------------------------------------------------
# Subset of fields we actually send to the AI.
# Keeping only relevant fields reduces token usage and noise.
# ---------------------------------------------------------------------------
FIELDS_WE_CARE_ABOUT = [
    "timestamp", "action", "login", "dept", "cip",
    "url", "urlcat", "urlsupercat", "bytes_sent", "bytes_received",
    "riskscore", "threatseverity", "threatname", "malwarecat",
    "dstip_country", "is_dst_cntry_risky", "bwthrottle"
]


def parse_log_file(file_path: str) -> list[dict]:
    """
    Reads a ZScaler log file and returns a list of parsed event dicts.

    Each line in the log is pipe-delimited ( | ).
    Lines that are blank, start with '#', or have too few fields are skipped.

    Args:
        file_path: Path to the .log or .txt file on disk.

    Returns:
        A list of dicts, one per valid log line, containing only the
        fields listed in FIELDS_WE_CARE_ABOUT.
    """
    events = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines and comment lines (e.g. file headers)
            if not line or line.startswith("#"):
                continue

            # Split the line into individual fields using the pipe delimiter
            parts = line.split("|")

            # Skip lines that don't have the expected number of fields
            if len(parts) < len(FIELD_NAMES):
                continue

            # Map each value to its field name using the FIELD_NAMES list
            raw = dict(zip(FIELD_NAMES, parts))

            # Keep only the fields we care about
            event = {key: raw[key] for key in FIELDS_WE_CARE_ABOUT if key in raw}

            # Convert byte and risk fields from strings to integers
            # so we can do math on them in get_summary_stats()
            try:
                event["bytes_sent"] = int(event.get("bytes_sent", 0))
                event["bytes_received"] = int(event.get("bytes_received", 0))
                event["riskscore"] = int(event.get("riskscore", 0))
            except ValueError:
                # If the value is non-numeric (e.g. "-" or empty), default to 0
                event["bytes_sent"] = 0
                event["bytes_received"] = 0
                event["riskscore"] = 0

            events.append(event)

    return events


def get_summary_stats(events: list[dict]) -> dict:
    """
    Computes high-level statistics across all parsed log events.

    These stats are included in the prompt sent to Claude so the AI
    has a quick overview before reading individual events.

    Args:
        events: List of parsed event dicts from parse_log_file().

    Returns:
        A dict with aggregate counts and notable data points, or an
        empty dict if no events were provided.
    """
    if not events:
        return {}

    total = len(events)

    # Count how many requests were blocked vs allowed by the proxy
    blocked = sum(1 for e in events if e.get("action") == "BLOCK")
    allowed = sum(1 for e in events if e.get("action") == "ALLOW")

    # Count events with a risk score of 75 or above (considered high risk)
    high_risk = sum(1 for e in events if int(e.get("riskscore", 0)) >= 75)

    # Total bytes sent across all events (useful for detecting data exfiltration)
    total_bytes_sent = sum(e.get("bytes_sent", 0) for e in events)

    # Count how many events each user generated
    user_counts = {}
    for e in events:
        user = e.get("login", "unknown")
        user_counts[user] = user_counts.get(user, 0) + 1

    # Collect the set of destination countries flagged as risky
    risky_countries = set(
        e.get("dstip_country") for e in events
        if e.get("is_dst_cntry_risky") == "Yes"
    )

    return {
        "total_events": total,
        "allowed": allowed,
        "blocked": blocked,
        "high_risk_events": high_risk,
        "total_bytes_sent": total_bytes_sent,
        "top_users": user_counts,
        "risky_countries_contacted": list(risky_countries)
    }
