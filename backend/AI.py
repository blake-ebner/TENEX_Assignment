# ---------------------------------------------------------------------------
# ai.py
# Sends parsed log data to Claude and returns a structured analysis report.
# Uses the Anthropic Python SDK to call the claude-opus-4-5 model.
# ---------------------------------------------------------------------------

import anthropic
import json
import os
from dotenv import load_dotenv

# Load ANTHROPIC_API_KEY from the .env file
load_dotenv()

# Initialize the Anthropic client using the API key from the environment
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def analyze_logs(events: list[dict], summary_stats: dict) -> dict:
    """
    Sends log events and summary statistics to Claude for SOC analysis.

    To keep token usage reasonable, only the first 150 events are included
    in the prompt. The summary_stats dict provides Claude with an overview
    of the full dataset even when events are truncated.

    Args:
        events:        Full list of parsed log event dicts.
        summary_stats: Aggregate stats from get_summary_stats().

    Returns:
        A dict with keys: summary, risk_level, timeline, anomalies,
        top_users, threat_breakdown, recommendations.
    """

    # Only send the first 150 events to keep the prompt within token limits
    sample = events[:150]

    # ---------------------------------------------------------------------------
    # Prompt
    # We instruct Claude to act as a SOC analyst and return structured JSON.
    # The schema is defined inline so the output is predictable and parseable.
    # ---------------------------------------------------------------------------
    prompt = f"""
You are a senior SOC (Security Operations Center) analyst reviewing ZScaler web proxy logs.
Analyze the following log events and summary statistics, then return a JSON response.

SUMMARY STATISTICS:
{json.dumps(summary_stats, indent=2)}

LOG EVENTS (up to 150 most recent):
{json.dumps(sample, indent=2)}

Return ONLY a valid JSON object with exactly this structure, no extra text:
{{
    "summary": "2-3 sentence plain English overview of what happened in this log file",
    "risk_level": "Critical | High | Medium | Low",
    "timeline": [
        {{
            "timestamp": "the timestamp from the log",
            "event": "plain English description of what happened",
            "severity": "Critical | High | Medium | Low | Info"
        }}
    ],
    "anomalies": [
        {{
            "timestamp": "the timestamp from the log",
            "user": "the login field",
            "url": "the url field",
            "reason": "plain English explanation of why this is suspicious",
            "confidence": 0.0
        }}
    ],
    "top_users": [
        {{
            "user": "login email",
            "event_count": 0,
            "risk_note": "brief note about this user's activity"
        }}
    ],
    "threat_breakdown": {{
        "malware_attempts": 0,
        "data_loss_events": 0,
        "policy_violations": 0,
        "network_scans": 0,
        "c2_communications": 0
    }},
    "recommendations": [
        "actionable recommendation for the SOC analyst"
    ]
}}

Rules:
- confidence scores must be between 0.0 and 1.0
- only include genuine anomalies, not normal traffic
- timeline should include the 10 most significant events in chronological order
- recommendations should be specific and actionable
- if the log looks normal with no threats, say so clearly in the summary and return empty anomalies array
"""

    # Send the prompt to Claude and wait for the response
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4000,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    # Extract the raw text from the first content block in the response
    raw_text = response.content[0].text

    # ---------------------------------------------------------------------------
    # Strip markdown code fences if Claude wrapped the JSON in a code block.
    # Claude sometimes returns ```json ... ``` even when told not to.
    # ---------------------------------------------------------------------------
    if "```json" in raw_text:
        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
    elif "```" in raw_text:
        raw_text = raw_text.split("```")[1].split("```")[0].strip()

    # Parse the cleaned JSON string into a Python dict and return it
    result = json.loads(raw_text)
    return result
