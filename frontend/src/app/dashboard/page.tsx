// -----------------------------------------------------------------------
// app/dashboard/page.tsx — Analysis Results Dashboard
//
// This is the main page of the app. It reads the upload_id from the URL,
// calls the backend to run Claude AI analysis on the uploaded log file,
// and then displays the full results in a SOC-style dashboard.
//
// The page has three possible states:
//   1. Loading — spinner shown while waiting for Claude to finish (~20s)
//   2. Error   — something went wrong (e.g. bad API key, expired token)
//   3. Results — the full dashboard with all sections rendered
// -----------------------------------------------------------------------

'use client' // Uses hooks (useEffect, useState, useSearchParams) so must run in browser

import { useEffect, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { analyzeUpload } from '@/lib/api' // Calls POST /api/analyze/{upload_id}

// -----------------------------------------------------------------------
// TypeScript interfaces — these describe the shape of data coming back
// from the backend. They match exactly what Claude returns in its JSON.
// -----------------------------------------------------------------------

interface TimelineItem {
  timestamp: string  // When the event happened
  event: string      // Plain-English description of the event
  severity: string   // Critical | High | Medium | Low | Info
}

interface AnomalyItem {
  timestamp: string  // When the suspicious event occurred
  user: string       // Which user triggered it
  url: string        // The URL that was flagged
  reason: string     // Claude's explanation of why it's suspicious
  confidence: number // 0.0 to 1.0 — how confident Claude is (e.g. 0.92 = 92%)
}

interface TopUser {
  user: string        // Username / email
  event_count: number // Total number of log events for this user
  risk_note: string   // Claude's short note about this user's activity
}

interface ThreatBreakdown {
  malware_attempts: number   // Times malware was detected or blocked
  data_loss_events: number   // Potential data exfiltration events
  policy_violations: number  // Blocked or flagged policy violations
  network_scans: number      // Internal network scanning activity
  c2_communications: number  // Command-and-control (botnet) traffic
}

// The full result object returned by the backend after analysis
interface Result {
  summary: string                  // 2-3 sentence plain English overview from Claude
  timeline: TimelineItem[]         // List of significant events in order
  anomalies: AnomalyItem[]         // List of suspicious/flagged events
  top_users: TopUser[]             // Most active users with risk context
  threat_breakdown: ThreatBreakdown
  created_at: string               // When the analysis was run
}

// -----------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------

// Returns a Tailwind text color class based on severity level
// Used in the timeline to color-code each event's severity label
const sevColor = (s: string) =>
  ({ Critical: 'text-red-400', High: 'text-orange-400', Medium: 'text-yellow-400', Low: 'text-green-400', Info: 'text-blue-400' }[s] ?? 'text-gray-400')

// Returns a Tailwind background color class for the risk level badge
const riskBg = (r: string) =>
  ({ Critical: 'bg-red-600', High: 'bg-orange-500', Medium: 'bg-yellow-500', Low: 'bg-green-600' }[r] ?? 'bg-gray-600')

// Computes an overall risk level from the threat breakdown counts.
// The backend doesn't persist risk_level to the DB, so we calculate it here.
function computeRisk(d: Result): string {
  const t = d.threat_breakdown
  if (t.c2_communications > 0 || t.malware_attempts > 5) return 'Critical'
  if (t.malware_attempts > 0 || t.data_loss_events > 3)  return 'High'
  if (t.policy_violations > 5 || d.anomalies.length > 3) return 'Medium'
  return 'Low'
}

// Generates actionable SOC recommendations based on what was found.
// One recommendation is added per threat category that has a non-zero count.
function genRecs(d: Result): string[] {
  const t = d.threat_breakdown
  const r: string[] = []
  if (t.c2_communications > 0) r.push(`Block ${t.c2_communications} C2 communication endpoint(s) and initiate incident response immediately`)
  if (t.malware_attempts > 0)  r.push(`Investigate ${t.malware_attempts} malware attempt(s) — isolate affected hosts and run endpoint scans`)
  if (t.data_loss_events > 0)  r.push(`Review ${t.data_loss_events} potential data loss event(s) and validate DLP policy coverage`)
  if (t.policy_violations > 0) r.push(`Remediate ${t.policy_violations} policy violation(s) and review user access entitlements`)
  if (t.network_scans > 0)     r.push(`Investigate network scanning activity from internal hosts — possible lateral movement`)
  if (d.anomalies.length > 0)  r.push(`Follow up with users involved in ${d.anomalies.length} flagged anomaly event(s)`)
  // If nothing bad was found, give a clean bill of health
  if (!r.length) r.push('No critical threats detected. Continue routine monitoring and baseline tuning.')
  return r
}

// -----------------------------------------------------------------------
// Main component
// -----------------------------------------------------------------------

export default function DashboardPage() {
  // Read the upload_id from the URL, e.g. /dashboard?upload_id=abc-123
  const params = useSearchParams()
  const router = useRouter()

  // The full analysis result from Claude (null until the API call completes)
  const [data, setData] = useState<Result | null>(null)

  // True while waiting for the backend/Claude to respond
  const [loading, setLoading] = useState(true)

  // Error message to display if the analysis call fails
  const [error, setError] = useState('')

  // On page load, kick off the analysis request
  useEffect(() => {
    const id = params.get('upload_id')

    // If there's no upload_id in the URL, send back to upload page
    if (!id) { router.push('/upload'); return }

    // If there's no token, the user isn't logged in — send to login
    if (!localStorage.getItem('token')) { router.push('/login'); return }

    // Call the backend to run Claude analysis and get back the results
    // This is the slow call — Claude takes 10-20 seconds to respond
    analyzeUpload(id)
      .then(setData)   // On success, store the results in state
      .catch((e: unknown) => {
        const err = e as { response?: { data?: { detail?: string } } }
        setError(err.response?.data?.detail || 'Analysis failed. Please try again.')
      })
      .finally(() => setLoading(false))
  }, [params, router])

  // ---- Loading state ----
  // Show a spinner and message while Claude is working
  if (loading) return (
    <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center gap-4">
      <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      <p className="text-gray-400 text-sm">Claude is analyzing your logs&hellip; this may take 20 seconds</p>
    </div>
  )

  // ---- Error state ----
  // Show the error message with a button to go back and try again
  if (error) return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
      <div className="text-center space-y-4">
        <p className="text-red-400">{error}</p>
        <button onClick={() => router.push('/upload')} className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm">
          Back to Upload
        </button>
      </div>
    </div>
  )

  // Shouldn't normally reach this, but guard against null data just in case
  if (!data) return null

  // ---- Pre-compute values used in the render ----
  const risk = computeRisk(data)   // e.g. "Critical"
  const recs = genRecs(data)       // Array of recommendation strings

  const t = data.threat_breakdown

  // The 5 threat stat cards shown at the top of the dashboard
  const threatStats = [
    { label: 'Malware Attempts',  value: t.malware_attempts,   color: 'text-red-400' },
    { label: 'Data Loss Events',  value: t.data_loss_events,   color: 'text-orange-400' },
    { label: 'Policy Violations', value: t.policy_violations,  color: 'text-yellow-400' },
    { label: 'Network Scans',     value: t.network_scans,      color: 'text-purple-400' },
    { label: 'C2 Communications', value: t.c2_communications,  color: 'text-red-500' },
  ]

  // ---- Dashboard render ----
  return (
    <div className="min-h-screen bg-gray-950 text-white">

      {/* Sticky header bar at the top of every dashboard page */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 className="text-lg font-bold text-blue-400">TENEX SOC Analyzer</h1>
          <p className="text-xs text-gray-500">Analysis completed &middot; {new Date(data.created_at).toLocaleString()}</p>
        </div>
        {/* Takes the user back to /upload to analyze another file */}
        <button onClick={() => router.push('/upload')} className="text-sm text-gray-400 hover:text-white transition-colors">
          + New Analysis
        </button>
      </header>

      <main className="max-w-7xl mx-auto p-6 space-y-5">

        {/* ---- Section 1: AI Summary + Risk Level Badge ----
            Two cards side by side. The summary takes up 2/3 of the width.
            The risk badge takes the remaining 1/3.                         */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 bg-gray-900 rounded-xl p-5 border border-gray-800">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">AI Summary</p>
            {/* Claude's plain-English description of what happened in the log */}
            <p className="text-gray-200 leading-relaxed">{data.summary}</p>
          </div>
          <div className="bg-gray-900 rounded-xl p-5 border border-gray-800 flex flex-col items-center justify-center gap-3">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Overall Risk</p>
            {/* The badge color changes based on the risk level (red=Critical, etc.) */}
            <span className={`px-8 py-2 rounded-full text-white font-bold text-xl ${riskBg(risk)}`}>{risk}</span>
            <p className="text-xs text-gray-500">{data.anomalies.length} anomalies &middot; {data.timeline.length} events</p>
          </div>
        </div>

        {/* ---- Section 2: Threat Breakdown ----
            Five stat cards in a row, one per threat category.
            Numbers are colored red/orange/yellow based on severity.        */}
        <div className="grid grid-cols-5 gap-3">
          {threatStats.map(({ label, value, color }) => (
            <div key={label} className="bg-gray-900 rounded-xl p-4 border border-gray-800 text-center">
              <p className={`text-3xl font-bold ${color}`}>{value}</p>
              <p className="text-xs text-gray-500 mt-1 leading-tight">{label}</p>
            </div>
          ))}
        </div>

        {/* ---- Section 3: Timeline + Top Users (side by side) ---- */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Event Timeline — chronological list of the 10 most significant events */}
          <div className="bg-gray-900 rounded-xl border border-gray-800">
            <div className="px-5 py-4 border-b border-gray-800">
              <h2 className="font-semibold text-gray-200">Event Timeline</h2>
              <p className="text-xs text-gray-500 mt-0.5">{data.timeline.length} significant events</p>
            </div>
            {/* Scrollable list — max height keeps it from taking over the page */}
            <div className="overflow-auto max-h-80">
              {data.timeline.length > 0 ? data.timeline.map((e, i) => (
                <div key={i} className="px-5 py-3 border-b border-gray-800/50 flex gap-3 items-start">
                  {/* Severity label colored by sevColor() — e.g. Critical = red */}
                  <span className={`text-xs font-semibold shrink-0 mt-0.5 w-14 ${sevColor(e.severity)}`}>{e.severity}</span>
                  <div className="min-w-0">
                    <p className="text-xs text-gray-300 leading-snug">{e.event}</p>
                    <p className="text-xs text-gray-600 mt-0.5">{e.timestamp}</p>
                  </div>
                </div>
              )) : <p className="px-5 py-5 text-gray-500 text-sm">No significant events recorded.</p>}
            </div>
          </div>

          {/* Top Users — who generated the most log activity, with risk notes */}
          <div className="bg-gray-900 rounded-xl border border-gray-800">
            <div className="px-5 py-4 border-b border-gray-800">
              <h2 className="font-semibold text-gray-200">Top Users by Activity</h2>
              <p className="text-xs text-gray-500 mt-0.5">{data.top_users.length} users tracked</p>
            </div>
            <div className="overflow-auto max-h-80">
              {data.top_users.length > 0 ? data.top_users.map((u, i) => (
                <div key={i} className="px-5 py-3 border-b border-gray-800/50 flex justify-between items-start gap-3">
                  <div className="min-w-0">
                    <p className="text-sm text-gray-200 truncate">{u.user}</p>
                    {/* Claude's risk note, e.g. "Accessed malware domains multiple times" */}
                    <p className="text-xs text-gray-500 mt-0.5">{u.risk_note}</p>
                  </div>
                  <span className="text-xs text-blue-400 shrink-0 font-medium">{u.event_count} events</span>
                </div>
              )) : <p className="px-5 py-5 text-gray-500 text-sm">No user data available.</p>}
            </div>
          </div>
        </div>

        {/* ---- Section 4: Anomalies Table ----
            Rows are highlighted red to draw attention to suspicious events.
            Confidence is shown as a percentage — higher = more certain it's bad. */}
        <div className="bg-gray-900 rounded-xl border border-gray-800">
          <div className="px-5 py-4 border-b border-gray-800">
            <h2 className="font-semibold text-gray-200">Anomalies & Suspicious Activity</h2>
            <p className="text-xs text-gray-500 mt-0.5">{data.anomalies.length} item(s) flagged by Claude AI</p>
          </div>
          {data.anomalies.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="px-5 py-3 text-left font-medium">Timestamp</th>
                    <th className="px-5 py-3 text-left font-medium">User</th>
                    <th className="px-5 py-3 text-left font-medium">URL</th>
                    <th className="px-5 py-3 text-left font-medium">Reason</th>
                    <th className="px-5 py-3 text-left font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.anomalies.map((a, i) => (
                    // Each row has a subtle red background to flag it as suspicious
                    <tr key={i} className="border-b border-gray-800/40 bg-red-950/10 hover:bg-red-950/20 transition-colors">
                      <td className="px-5 py-3 text-gray-500 whitespace-nowrap">{a.timestamp}</td>
                      <td className="px-5 py-3 text-gray-300">{a.user}</td>
                      <td className="px-5 py-3 text-blue-400 max-w-xs truncate">{a.url}</td>
                      <td className="px-5 py-3 text-gray-300 max-w-sm">{a.reason}</td>
                      <td className="px-5 py-3">
                        {/* Confidence color: red = high certainty threat, yellow = medium, green = low */}
                        <span className={`font-bold ${a.confidence > 0.7 ? 'text-red-400' : a.confidence > 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {(a.confidence * 100).toFixed(0)}%
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="px-5 py-6 text-gray-500 text-sm">No anomalies detected. Traffic appears normal.</p>
          )}
        </div>

        {/* ---- Section 5: SOC Recommendations ----
            Auto-generated action items based on what threats were found.
            One bullet per threat category with a non-zero count.           */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="font-semibold text-gray-200 mb-4">SOC Recommendations</h2>
          <ul className="space-y-2.5">
            {recs.map((rec, i) => (
              <li key={i} className="flex gap-3 text-sm text-gray-300">
                <span className="text-blue-400 shrink-0 font-bold">&rarr;</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>

      </main>
    </div>
  )
}
