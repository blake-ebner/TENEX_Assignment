# ---------------------------------------------------------------------------
# parser.py
# Parses ZScaler web proxy log files into structured Python dicts.
# Also computes summary statistics and selects which events are worth
# sending to the AI when a log is too large to send in full.
# ---------------------------------------------------------------------------

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

# A line must have at least enough columns to cover every field we read.
# Lines shorter than this are malformed and get skipped.
MIN_FIELDS = max(FIELD_NAMES.index(f) for f in FIELDS_WE_CARE_ABOUT) + 1

# Fields that should be integers rather than strings, so we can do math on them
NUMERIC_FIELDS = ("bytes_sent", "bytes_received", "riskscore")

# Placeholder values ZScaler writes when a field has no value
EMPTY_VALUES = {"", "-", "none", "null", "na", "n/a"}

# URL categories that are inherently suspicious regardless of risk score
HIGH_RISK_CATEGORIES = {
    "malware", "botnet", "botnets", "spyware", "phishing", "adware",
    "peer to peer", "p2p", "anonymizer", "unauthorized communication",
    "command and control", "c2", "cryptomining", "newly registered domains",
    "suspicious destinations", "malicious",
}

# Ranking used to turn ZScaler's threat severity strings into a number
SEVERITY_WEIGHTS = {"critical": 60, "high": 45, "medium": 25, "low": 10}


def _is_empty(value) -> bool:
    """True if a field is blank or one of ZScaler's placeholder values."""
    return str(value).strip().lower() in EMPTY_VALUES


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

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines and comment lines (e.g. file headers)
            if not line or line.startswith("#"):
                continue

            # Split the line into individual fields using the pipe delimiter
            parts = line.split("|")

            # Skip lines too short to contain the fields we read
            if len(parts) < MIN_FIELDS:
                continue

            # Map each value to its field name using the FIELD_NAMES list
            raw = dict(zip(FIELD_NAMES, parts))

            # Keep only the fields we care about
            event = {key: raw[key] for key in FIELDS_WE_CARE_ABOUT if key in raw}

            # Convert byte and risk fields from strings to integers.
            # Each field is converted independently — one bad value (e.g. "-")
            # must not wipe out the other two.
            for field in NUMERIC_FIELDS:
                try:
                    event[field] = int(str(event.get(field, "0")).strip())
                except (ValueError, TypeError):
                    event[field] = 0

            events.append(event)

    return events


def score_event(event: dict, large_transfer_bytes: int) -> int:
    """
    Scores how interesting a single event is to a SOC analyst.

    Used to decide which events to send to the AI when a log file is
    larger than the prompt can hold. Higher score = more worth reviewing.

    Args:
        event:                A parsed event dict from parse_log_file().
        large_transfer_bytes: Byte threshold above which an outbound transfer
                              counts as unusually large for this file.

    Returns:
        An integer score. Routine, allowed, low-risk browsing scores near 0.
    """
    score = 0

    # ZScaler's own risk score is the strongest single signal (0-100)
    score += max(0, min(100, event.get("riskscore", 0)))

    # The proxy already decided this request was worth stopping
    if str(event.get("action", "")).upper() == "BLOCK":
        score += 40

    # Named threats and malware classifications are explicit detections
    if not _is_empty(event.get("threatname")):
        score += 60
    if not _is_empty(event.get("malwarecat")):
        score += 50

    # Traffic to a country the org flags as risky
    if str(event.get("is_dst_cntry_risky", "")).strip().lower() == "yes":
        score += 30

    # Categories that are suspicious on their own
    for field in ("urlcat", "urlsupercat"):
        value = str(event.get(field, "")).strip().lower()
        if any(cat in value for cat in HIGH_RISK_CATEGORIES):
            score += 40
            break

    # Large outbound transfers are the classic exfiltration signal
    if large_transfer_bytes and event.get("bytes_sent", 0) >= large_transfer_bytes:
        score += 35

    # ZScaler's threat severity rating, if present
    score += SEVERITY_WEIGHTS.get(
        str(event.get("threatseverity", "")).strip().lower(), 0
    )

    return score


def select_significant_events(events: list[dict], limit: int = 150) -> list[dict]:
    """
    Picks which events to send to the AI when the log is too large to send whole.

    Sending the first N lines would mean a 20,000-line log is judged on its
    first few minutes. Instead we send the highest-scoring events plus an
    even sample of the rest, so the AI sees both the threats and the baseline
    of normal traffic they stand out against.

    The returned events stay in their original file order so timestamps in
    the AI's timeline remain chronological.

    Args:
        events: Full list of parsed event dicts.
        limit:  Maximum number of events to return.

    Returns:
        A list of exactly `limit` events in original file order, or every
        event if the file is smaller than `limit`.
    """
    if len(events) <= limit:
        return events

    # Work out what counts as a "large" transfer for this particular file,
    # rather than using a fixed byte count that suits no log in particular.
    sent = sorted(e.get("bytes_sent", 0) for e in events)
    p95 = sent[int(len(sent) * 0.95)] if sent else 0
    large_transfer_bytes = max(p95, 1)

    # Reserve a fifth of the budget for a spread of ordinary traffic so the
    # AI can tell what "normal" looks like in this environment.
    baseline_budget = max(1, limit // 5)
    signal_budget = limit - baseline_budget

    scored = sorted(
        range(len(events)),
        key=lambda i: score_event(events[i], large_transfer_bytes),
        reverse=True,
    )
    chosen = set(scored[:signal_budget])

    # Walk the file at a fixed stride to fill the baseline slots
    stride = max(1, len(events) // baseline_budget)
    for i in range(0, len(events), stride):
        if len(chosen) >= limit:
            break
        chosen.add(i)

    # The stride lands on events already picked for their score whenever the
    # threats are clustered, which would leave part of the budget unspent.
    # Top up with the next-highest scorers so we always send a full prompt.
    for i in scored[signal_budget:]:
        if len(chosen) >= limit:
            break
        chosen.add(i)

    return [events[i] for i in sorted(chosen)]


def get_summary_stats(events: list[dict]) -> dict:
    """
    Computes high-level statistics across all parsed log events.

    These stats are included in the prompt sent to Claude so the AI has an
    overview of the *entire* file even when only a sample of events is sent.

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
    blocked = sum(1 for e in events if str(e.get("action", "")).upper() == "BLOCK")
    allowed = sum(1 for e in events if str(e.get("action", "")).upper() == "ALLOW")

    # Count events with a risk score of 75 or above (considered high risk)
    high_risk = sum(1 for e in events if e.get("riskscore", 0) >= 75)

    # Total bytes moved in each direction (useful for spotting exfiltration)
    total_bytes_sent = sum(e.get("bytes_sent", 0) for e in events)
    total_bytes_received = sum(e.get("bytes_received", 0) for e in events)

    # Count how many events each user generated
    user_counts = {}
    for e in events:
        user = e.get("login", "unknown")
        user_counts[user] = user_counts.get(user, 0) + 1

    # Only the busiest users go in the prompt — a large log can have thousands
    top_users = dict(
        sorted(user_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]
    )

    # Collect destination countries flagged as risky.
    # Sorted so the prompt is byte-identical for identical input, which keeps
    # prompt caching effective (a set's iteration order is not stable).
    risky_countries = sorted({
        e.get("dstip_country") for e in events
        if str(e.get("is_dst_cntry_risky", "")).strip().lower() == "yes"
    })

    return {
        "total_events": total,
        "allowed": allowed,
        "blocked": blocked,
        "high_risk_events": high_risk,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_received": total_bytes_received,
        "unique_users": len(user_counts),
        "top_users": top_users,
        "risky_countries_contacted": risky_countries,
        "first_event": events[0].get("timestamp"),
        "last_event": events[-1].get("timestamp"),
    }
