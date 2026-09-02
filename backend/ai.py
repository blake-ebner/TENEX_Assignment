# ---------------------------------------------------------------------------
# ai.py
# Sends parsed log data to Claude and returns a structured analysis report.
#
# The report shape is declared as Pydantic models and passed to the API as a
# structured output schema. Claude's response is guaranteed to match it, so
# there is no markdown-fence stripping or hand-rolled JSON parsing to go wrong.
#
# The client is async so a 15-20 second analysis does not block the FastAPI
# event loop and freeze every other request.
# ---------------------------------------------------------------------------

import json
import os

from anthropic import AsyncAnthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Imported so the prompt's field list cannot drift from what the parser
# actually sends — a Sigma rule referencing a field we don't emit is useless.
from parser import FIELDS_WE_CARE_ABOUT

# Load ANTHROPIC_API_KEY from the .env file
load_dotenv()

# Identity-linked API keys must name the workspace each request acts in, or the
# API rejects the call with a 400. Standard keys have no such requirement, so
# the header is only sent when a workspace ID is actually configured.
WORKSPACE_ID = os.getenv("ANTHROPIC_WORKSPACE_ID")

# Initialize the Anthropic client using the API key from the environment
client = AsyncAnthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    default_headers={"anthropic-workspace-id": WORKSPACE_ID} if WORKSPACE_ID else None,
)

MODEL = "claude-opus-5"

# Maximum number of log events included in the prompt. The full file is always
# reflected in the summary statistics; parser.select_significant_events() picks
# which individual events are worth the token budget.
MAX_EVENTS_IN_PROMPT = 150


# ---------------------------------------------------------------------------
# Report schema
# These models define exactly what Claude must return. The API enforces the
# schema, so every field below is guaranteed present and correctly typed.
# ---------------------------------------------------------------------------

class TimelineEntry(BaseModel):
    timestamp: str = Field(description="The timestamp from the log event")
    event: str = Field(description="Plain English description of what happened")
    severity: str = Field(description="One of: Critical, High, Medium, Low, Info")


class AttackTechnique(BaseModel):
    """One MITRE ATT&CK technique an anomaly maps to."""

    id: str = Field(
        description="MITRE ATT&CK technique ID, e.g. T1071.001 or T1041. "
                    "Use only real technique IDs you are confident exist."
    )
    name: str = Field(
        description="The technique's official ATT&CK name, e.g. 'Web Protocols'"
    )


class Anomaly(BaseModel):
    timestamp: str = Field(description="The timestamp from the log event")
    user: str = Field(description="The login field from the event")
    url: str = Field(description="The url field from the event")
    reason: str = Field(description="Plain English explanation of why this is suspicious")
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="How confident you are that this is a genuine threat, 0.0 to 1.0",
    )
    attack_techniques: list[AttackTechnique] = Field(
        description="MITRE ATT&CK techniques this event maps to. Empty list if "
                    "no technique applies — do not force a mapping."
    )


class DetectionRule(BaseModel):
    """A deployable Sigma rule that would catch this activity next time."""

    title: str = Field(description="Short rule title, e.g. 'Outbound transfer to risky geography'")
    description: str = Field(
        description="One or two sentences on what this rule catches and why it matters"
    )
    severity: str = Field(description="One of: critical, high, medium, low")
    sigma: str = Field(
        description="The complete Sigma rule as valid YAML, ready to paste into a SIEM"
    )


class TopUser(BaseModel):
    user: str = Field(description="Login email of the user")
    event_count: int = Field(description="Number of events this user generated")
    risk_note: str = Field(description="Brief note about this user's activity")


class ThreatBreakdown(BaseModel):
    malware_attempts: int
    data_loss_events: int
    policy_violations: int
    network_scans: int
    c2_communications: int


class SocAnalysis(BaseModel):
    """The complete SOC report Claude returns for one log file."""

    summary: str = Field(
        description="2-3 sentence plain English overview of what happened in this log file"
    )
    risk_level: str = Field(description="Overall risk: Critical, High, Medium, or Low")
    timeline: list[TimelineEntry] = Field(
        description="The 10 most significant events, in chronological order"
    )
    anomalies: list[Anomaly] = Field(
        description="Genuinely suspicious events only — empty if the traffic is normal"
    )
    top_users: list[TopUser] = Field(description="Most active users, with risk context")
    threat_breakdown: ThreatBreakdown
    recommendations: list[str] = Field(
        description="Specific, actionable next steps for the SOC analyst"
    )
    detections: list[DetectionRule] = Field(
        description="Sigma rules that would detect the confirmed findings in future "
                    "traffic. Empty list if nothing worth alerting on was found."
    )


SYSTEM_PROMPT = f"""You are a senior SOC (Security Operations Center) analyst \
reviewing ZScaler web proxy logs.

Analyse the events you are given and report what a SOC team needs to act on.

Rules:
- Only flag genuine anomalies. Routine browsing and normal SaaS usage are not anomalies.
- Confidence reflects how many independent signals corroborate a finding: a high
  risk score alone is weaker evidence than a high risk score plus a malware
  category plus a large outbound transfer to a risky country.
- The timeline should hold the 10 most significant events in chronological order.
- Recommendations must be specific and actionable, not generic security advice.
- If the traffic looks normal, say so plainly in the summary, return an empty
  anomalies list, and set risk_level to Low. Do not invent threats to fill the report.

MITRE ATT&CK mapping:
- Map each anomaly to the ATT&CK techniques it genuinely demonstrates, using real
  technique IDs and their official names.
- Accuracy matters far more than coverage. An empty list is the correct answer for
  an event that doesn't clearly demonstrate a technique — a wrong or invented
  technique ID is worse than none, because an analyst will act on it.
- Prefer the specific sub-technique when the evidence supports it, otherwise the
  parent technique.

Detection rules:
- Write Sigma rules for the findings worth alerting on in future traffic. Fewer,
  well-targeted rules beat one rule per anomaly; a single rule often covers a
  whole class of finding.
- The `sigma` field must be complete, valid Sigma YAML with at minimum: title,
  status, description, logsource, detection (with a condition), falsepositives,
  and level.
- Write detection logic against these field names only — they are exactly what
  this pipeline parses out of the log:
  {", ".join(FIELDS_WE_CARE_ABOUT)}
- Rules must be specific enough to be deployable. A rule that fires on all
  outbound traffic is worse than no rule, so include thresholds and qualifiers
  that reflect what you actually observed.
- If nothing in the file warrants an alert, return an empty detections list.
"""


async def analyze_logs(events: list[dict], summary_stats: dict) -> dict:
    """
    Sends log events and summary statistics to Claude for SOC analysis.

    Large files are sampled rather than truncated: the summary statistics
    always describe every event in the file, while the individual events in
    the prompt are the most significant ones plus a spread of normal traffic.

    Args:
        events:        Events selected for the prompt (see
                       parser.select_significant_events).
        summary_stats: Aggregate stats for the whole file, from
                       parser.get_summary_stats().

    Returns:
        A dict matching SocAnalysis: summary, risk_level, timeline, anomalies,
        top_users, threat_breakdown, recommendations.

    Raises:
        RuntimeError: If Claude returns no parsed report (e.g. the response was
                      cut short by the token limit).
    """
    total_events = summary_stats.get("total_events", len(events))
    sampled = len(events) < total_events

    sampling_note = (
        f"\nNOTE: This file contains {total_events} events. You are seeing "
        f"{len(events)} of them — the most significant events plus a sample of "
        f"routine traffic for context. The summary statistics above cover all "
        f"{total_events} events.\n"
        if sampled else ""
    )

    prompt = f"""SUMMARY STATISTICS (entire log file):
{json.dumps(summary_stats, indent=2, sort_keys=True)}
{sampling_note}
LOG EVENTS:
{json.dumps(events, indent=2)}

Produce the SOC report."""

    response = await client.messages.parse(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
        output_format=SocAnalysis,
    )

    report = response.parsed_output
    if report is None:
        raise RuntimeError(
            f"Claude returned no structured report (stop_reason={response.stop_reason})"
        )

    return report.model_dump()
