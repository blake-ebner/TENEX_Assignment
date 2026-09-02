// -----------------------------------------------------------------------
// lib/report.ts — Shape of an analysis report, and Markdown export.
//
// The types here mirror what the backend returns from GET /api/results/{id},
// which in turn mirrors the SocAnalysis schema Claude is constrained to in
// backend/ai.py. Every field is persisted — nothing is recomputed in the UI.
//
// toMarkdown() exists because SOC analysts work in tickets: the fastest way
// to get a report into Jira/ServiceNow/Slack is to paste it as Markdown.
// -----------------------------------------------------------------------

export interface TimelineItem {
  timestamp: string  // When the event happened
  event: string      // Plain-English description of the event
  severity: string   // Critical | High | Medium | Low | Info
}

// A MITRE ATT&CK technique an anomaly maps to, e.g. T1041 / "Exfiltration Over
// C2 Channel". Every SOC tool speaks ATT&CK, so this is how a finding here gets
// compared against detections elsewhere.
export interface AttackTechnique {
  id: string   // e.g. "T1071.001"
  name: string // e.g. "Web Protocols"
}

export interface AnomalyItem {
  timestamp: string  // When the suspicious event occurred
  user: string       // Which user triggered it
  url: string        // The URL that was flagged
  reason: string     // Claude's explanation of why it's suspicious
  confidence: number // 0.0 to 1.0 — how confident Claude is (e.g. 0.92 = 92%)
  // Optional: reports generated before ATT&CK mapping was added won't have it
  attack_techniques?: AttackTechnique[]
}

// A deployable Sigma rule — the report doesn't just say what happened, it hands
// the analyst the detection that catches it next time.
export interface DetectionRule {
  title: string
  description: string
  severity: string // critical | high | medium | low
  sigma: string    // complete Sigma YAML
}

export interface TopUser {
  user: string        // Username / email
  event_count: number // Total number of log events for this user
  risk_note: string   // Claude's short note about this user's activity
}

export interface ThreatBreakdown {
  malware_attempts: number   // Times malware was detected or blocked
  data_loss_events: number   // Potential data exfiltration events
  policy_violations: number  // Blocked or flagged policy violations
  network_scans: number      // Internal network scanning activity
  c2_communications: number  // Command-and-control (botnet) traffic
}

// The full result object returned by GET /api/results/{upload_id}
export interface Result {
  filename: string                 // Original name of the uploaded log file
  summary: string                  // 2-3 sentence plain English overview from Claude
  risk_level: string               // Critical | High | Medium | Low — from Claude, not inferred
  timeline: TimelineItem[]         // List of significant events in order
  anomalies: AnomalyItem[]         // List of suspicious/flagged events
  top_users: TopUser[]             // Most active users with risk context
  threat_breakdown: ThreatBreakdown
  recommendations: string[]        // Actionable next steps — from Claude, not inferred
  detections?: DetectionRule[]     // Sigma rules; absent on pre-detections reports
  created_at: string               // When the analysis was run
}

// Human-readable labels for the threat_breakdown keys, in display order
export const THREAT_LABELS: [keyof ThreatBreakdown, string][] = [
  ['malware_attempts', 'Malware Attempts'],
  ['data_loss_events', 'Data Loss Events'],
  ['policy_violations', 'Policy Violations'],
  ['network_scans', 'Network Scans'],
  ['c2_communications', 'C2 Communications'],
]

// Escapes the pipe characters that would otherwise break a Markdown table row.
// ZScaler URLs and Claude's reasons can both legitimately contain them.
const cell = (value: string) => String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ')

/**
 * Renders a report as Markdown suitable for pasting into a ticket.
 *
 * Sections are omitted rather than left empty where an empty section would be
 * noise (an anomaly table with no rows), and stated plainly where the absence
 * is itself the finding ("No anomalies detected").
 */
export function toMarkdown(data: Result): string {
  const lines: string[] = []

  lines.push(`# SOC Analysis — ${data.filename}`)
  lines.push('')
  lines.push(`**Overall risk:** ${data.risk_level}`)
  lines.push(`**Analyzed:** ${new Date(data.created_at).toLocaleString()}`)
  lines.push('')

  lines.push('## Summary')
  lines.push('')
  lines.push(data.summary)
  lines.push('')

  lines.push('## Threat Breakdown')
  lines.push('')
  lines.push('| Category | Count |')
  lines.push('| --- | --- |')
  for (const [key, label] of THREAT_LABELS) {
    lines.push(`| ${label} | ${data.threat_breakdown?.[key] ?? 0} |`)
  }
  lines.push('')

  lines.push('## Anomalies')
  lines.push('')
  if (data.anomalies.length) {
    lines.push('| Timestamp | User | URL | Reason | ATT&CK | Confidence |')
    lines.push('| --- | --- | --- | --- | --- | --- |')
    for (const a of data.anomalies) {
      const attack = (a.attack_techniques ?? []).map((t) => t.id).join(', ') || '—'
      lines.push(
        `| ${cell(a.timestamp)} | ${cell(a.user)} | ${cell(a.url)} | ${cell(a.reason)} | ${cell(attack)} | ${(a.confidence * 100).toFixed(0)}% |`
      )
    }
  } else {
    lines.push('No anomalies detected. Traffic appears normal.')
  }
  lines.push('')

  // ATT&CK coverage, deduplicated across anomalies — the summary a reader wants
  // before reading any individual finding.
  const techniques = new Map<string, string>()
  for (const a of data.anomalies) {
    for (const t of a.attack_techniques ?? []) {
      if (t.id) techniques.set(t.id, t.name)
    }
  }
  if (techniques.size) {
    lines.push('## MITRE ATT&CK Coverage')
    lines.push('')
    for (const [id, name] of [...techniques].sort((a, b) => a[0].localeCompare(b[0]))) {
      lines.push(`- \`${id}\` — ${name}`)
    }
    lines.push('')
  }

  if (data.timeline.length) {
    lines.push('## Event Timeline')
    lines.push('')
    for (const e of data.timeline) {
      lines.push(`- **${e.severity}** — ${e.timestamp} — ${e.event}`)
    }
    lines.push('')
  }

  if (data.top_users.length) {
    lines.push('## Top Users')
    lines.push('')
    for (const u of data.top_users) {
      lines.push(`- **${u.user}** (${u.event_count} events) — ${u.risk_note}`)
    }
    lines.push('')
  }

  lines.push('## Recommendations')
  lines.push('')
  for (const rec of data.recommendations) {
    lines.push(`- ${rec}`)
  }
  lines.push('')

  // Sigma rules go in fenced yaml blocks so they survive the paste into a
  // ticket and can be lifted straight into a SIEM.
  if (data.detections?.length) {
    lines.push('## Detection Rules')
    lines.push('')
    for (const d of data.detections) {
      lines.push(`### ${d.title} (${d.severity})`)
      lines.push('')
      lines.push(d.description)
      lines.push('')
      lines.push('```yaml')
      lines.push(d.sigma.trimEnd())
      lines.push('```')
      lines.push('')
    }
  }

  lines.push('---')
  lines.push('_Generated by TENEX SOC Analyzer (Claude AI)._')

  return lines.join('\n')
}
