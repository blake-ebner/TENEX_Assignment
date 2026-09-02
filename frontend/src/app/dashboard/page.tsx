// -----------------------------------------------------------------------
// app/dashboard/page.tsx — Analysis Results Dashboard
//
// Reads upload_id from the URL, then drives the analysis pipeline:
//
//   1. POST /api/analyze/{id}        starts a background job, returns at once
//   2. GET  /api/analyze/{id}/status polled every ~1.5s for the current stage
//   3. GET  /api/results/{id}        fetched once the status is "done"
//
// Because the job runs on the server, the report survives a closed tab — a
// second visit to the same URL skips straight to step 3. Every field shown
// here comes from the stored report; nothing is recomputed in the browser.
// -----------------------------------------------------------------------

'use client' // Uses hooks (useEffect, useState, useSearchParams) so must run in browser

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { analyzeUpload, getAnalysisStatus, getResults } from '@/lib/api'
import {
  THREAT_LABELS,
  toMarkdown,
  type AnomalyItem,
  type DetectionRule,
  type Result,
} from '@/lib/report'

// How often to ask the backend which pipeline stage it is on
const POLL_INTERVAL_MS = 1500

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

// Anomalies carry a confidence score rather than a severity label, so the
// severity band shown (and filtered on) is derived from that one number —
// the same thresholds the confidence column is colored by.
const band = (confidence: number) =>
  confidence > 0.7 ? 'High' : confidence > 0.4 ? 'Medium' : 'Low'

const bandColor = (confidence: number) =>
  confidence > 0.7 ? 'text-red-400' : confidence > 0.4 ? 'text-yellow-400' : 'text-green-400'

type SortKey = 'confidence' | 'user' | 'timestamp'

// -----------------------------------------------------------------------
// Page shell
//
// useSearchParams causes the component tree up to the nearest Suspense
// boundary to be client-rendered; without this boundary a production build
// fails with "Missing Suspense boundary with useSearchParams".
// -----------------------------------------------------------------------

export default function DashboardPage() {
  return (
    <Suspense fallback={<Centered><p className="text-gray-400 text-sm">Loading&hellip;</p></Centered>}>
      <Dashboard />
    </Suspense>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center gap-4 p-8">
      {children}
    </div>
  )
}

// -----------------------------------------------------------------------
// Main component
// -----------------------------------------------------------------------

function Dashboard() {
  const params = useSearchParams()
  const router = useRouter()

  // Read once into a string: useSearchParams returns a fresh object on every
  // render, so depending on it directly would restart polling on each tick.
  const uploadId = params.get('upload_id')

  const [data, setData] = useState<Result | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Every pipeline stage the backend has reported so far, in order. Showing
  // the whole list rather than just the latest turns a 20-second wait into
  // visible progress instead of an unexplained spinner.
  const [stages, setStages] = useState<string[]>([])

  useEffect(() => {
    // If there's no upload_id in the URL, send back to the upload page
    if (!uploadId) { router.push('/upload'); return }

    // If there's no token, the user isn't logged in — send to login
    if (!localStorage.getItem('token')) { router.push('/login'); return }

    // Guards against setting state after the user has navigated away, and
    // against a poll that is still queued when the effect is torn down.
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const fail = (e: unknown, fallback: string) => {
      if (cancelled) return
      const err = e as { response?: { data?: { detail?: string } } }
      setError(err.response?.data?.detail || fallback)
      setLoading(false)
    }

    // Record a stage the first time we see it. The backend reports the same
    // stage on every poll until it moves on, so ignore repeats.
    const noteStage = (stage?: string | null) => {
      if (!stage) return
      setStages((prev) => (prev[prev.length - 1] === stage ? prev : [...prev, stage]))
    }

    // The analysis is finished — fetch the stored report
    const loadResults = async () => {
      try {
        const result = await getResults(uploadId)
        if (cancelled) return
        setData(result)
        setLoading(false)
      } catch (e) {
        fail(e, 'Could not load the analysis result.')
      }
    }

    const poll = async () => {
      try {
        const { status, stage, error: jobError } = await getAnalysisStatus(uploadId)
        if (cancelled) return

        if (status === 'done') { noteStage('Complete'); await loadResults(); return }

        if (status === 'error') {
          setError(jobError || 'Analysis failed. Please try again.')
          setLoading(false)
          return
        }

        noteStage(stage)
        timer = setTimeout(poll, POLL_INTERVAL_MS)
      } catch (e) {
        fail(e, 'Lost contact with the analysis job.')
      }
    }

    // Kick the job off. This returns immediately; an upload that was already
    // analyzed comes back as "done" and skips straight to the stored report.
    analyzeUpload(uploadId)
      .then(({ status, stage }) => {
        if (cancelled) return
        if (status === 'done') { loadResults(); return }
        noteStage(stage)
        timer = setTimeout(poll, POLL_INTERVAL_MS)
      })
      .catch((e) => fail(e, 'Analysis failed. Please try again.'))

    return () => { cancelled = true; if (timer) clearTimeout(timer) }
  }, [uploadId, router])

  // ---- Loading state ----
  // The stage list fills in as the backend works through the pipeline
  if (loading) return (
    <Centered>
      <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      <p className="text-gray-400 text-sm">Analyzing your logs&hellip;</p>
      <ol className="text-xs text-gray-500 space-y-1.5 min-w-64">
        {stages.map((stage, i) => {
          const current = i === stages.length - 1
          return (
            <li key={`${stage}-${i}`} className={`flex gap-2 ${current ? 'text-blue-400' : ''}`}>
              <span className="shrink-0">{current ? '›' : '✓'}</span>
              <span>{stage}</span>
            </li>
          )
        })}
      </ol>
    </Centered>
  )

  // ---- Error state ----
  if (error) return (
    <Centered>
      <p className="text-red-400 text-sm text-center max-w-md">{error}</p>
      <div className="flex gap-3">
        <button onClick={() => router.push('/upload')} className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm transition-colors">
          Back to Upload
        </button>
        <button onClick={() => router.push('/history')} className="px-5 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-xl text-sm transition-colors">
          My Analyses
        </button>
      </div>
    </Centered>
  )

  // Shouldn't normally reach this, but guard against null data just in case
  if (!data) return null

  return <Report data={data} />
}

// -----------------------------------------------------------------------
// Report — the dashboard itself, rendered from a completed analysis
// -----------------------------------------------------------------------

function Report({ data }: { data: Result }) {
  const router = useRouter()

  // ---- Anomaly table controls ----
  const [query, setQuery] = useState('')                 // free text over user/url/reason
  const [minBand, setMinBand] = useState('All')          // All | High | Medium
  const [sortKey, setSortKey] = useState<SortKey>('confidence')

  const anomalies = useMemo(() => {
    const needle = query.trim().toLowerCase()

    const filtered = data.anomalies.filter((a: AnomalyItem) => {
      if (minBand === 'High' && a.confidence <= 0.7) return false
      if (minBand === 'Medium' && a.confidence <= 0.4) return false
      if (!needle) return true
      return `${a.user} ${a.url} ${a.reason}`.toLowerCase().includes(needle)
    })

    // Copy before sorting — Array.sort mutates, and data.anomalies is state
    return [...filtered].sort((a, b) => {
      if (sortKey === 'confidence') return b.confidence - a.confidence  // most certain first
      if (sortKey === 'user') return a.user.localeCompare(b.user)
      return a.timestamp.localeCompare(b.timestamp)                     // ISO-ish, sorts chronologically
    })
  }, [data.anomalies, query, minBand, sortKey])

  const t = data.threat_breakdown

  // The 5 threat stat cards shown at the top of the dashboard
  const threatColors: Record<string, string> = {
    malware_attempts: 'text-red-400',
    data_loss_events: 'text-orange-400',
    policy_violations: 'text-yellow-400',
    network_scans: 'text-purple-400',
    c2_communications: 'text-red-500',
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white">

      {/* Sticky header bar at the top of every dashboard page */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between gap-4 sticky top-0 z-10">
        <div className="min-w-0">
          <h1 className="text-lg font-bold text-blue-400 truncate">{data.filename}</h1>
          <p className="text-xs text-gray-500">Analysis completed &middot; {new Date(data.created_at).toLocaleString()}</p>
        </div>
        <div className="flex items-center gap-4 shrink-0">
          <ExportButtons data={data} />
          <button onClick={() => router.push('/trends')} className="text-sm text-gray-400 hover:text-white transition-colors">
            Trends
          </button>
          <button onClick={() => router.push('/history')} className="text-sm text-gray-400 hover:text-white transition-colors">
            My Analyses
          </button>
          <button onClick={() => router.push('/upload')} className="text-sm text-gray-400 hover:text-white transition-colors">
            + New Analysis
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto p-6 space-y-5">

        {/* ---- Section 1: AI Summary + Risk Level Badge ---- */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 bg-gray-900 rounded-xl p-5 border border-gray-800">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">AI Summary</p>
            {/* Claude's plain-English description of what happened in the log */}
            <p className="text-gray-200 leading-relaxed">{data.summary}</p>
          </div>
          <div className="bg-gray-900 rounded-xl p-5 border border-gray-800 flex flex-col items-center justify-center gap-3">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Overall Risk</p>
            {/* Claude's own risk_level, stored with the report — not inferred here */}
            <span className={`px-8 py-2 rounded-full text-white font-bold text-xl ${riskBg(data.risk_level)}`}>{data.risk_level}</span>
            <p className="text-xs text-gray-500">{data.anomalies.length} anomalies &middot; {data.timeline.length} events</p>
          </div>
        </div>

        {/* ---- Section 2: Threat Breakdown ---- */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {THREAT_LABELS.map(([key, label]) => (
            <div key={key} className="bg-gray-900 rounded-xl p-4 border border-gray-800 text-center">
              <p className={`text-3xl font-bold ${threatColors[key]}`}>{t?.[key] ?? 0}</p>
              <p className="text-xs text-gray-500 mt-1 leading-tight">{label}</p>
            </div>
          ))}
        </div>

        {/* ---- Section 3: Timeline + Top Users (side by side) ---- */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Event Timeline — chronological list of the most significant events */}
          <div className="bg-gray-900 rounded-xl border border-gray-800">
            <div className="px-5 py-4 border-b border-gray-800">
              <h2 className="font-semibold text-gray-200">Event Timeline</h2>
              <p className="text-xs text-gray-500 mt-0.5">{data.timeline.length} significant events</p>
            </div>
            <div className="overflow-auto max-h-80">
              {data.timeline.length > 0 ? data.timeline.map((e, i) => (
                <div key={i} className="px-5 py-3 border-b border-gray-800/50 flex gap-3 items-start">
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
                    <p className="text-xs text-gray-500 mt-0.5">{u.risk_note}</p>
                  </div>
                  <span className="text-xs text-blue-400 shrink-0 font-medium">{u.event_count} events</span>
                </div>
              )) : <p className="px-5 py-5 text-gray-500 text-sm">No user data available.</p>}
            </div>
          </div>
        </div>

        {/* ---- Section 4: Anomalies Table ---- */}
        <div className="bg-gray-900 rounded-xl border border-gray-800">
          <div className="px-5 py-4 border-b border-gray-800 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="font-semibold text-gray-200">Anomalies &amp; Suspicious Activity</h2>
              <p className="text-xs text-gray-500 mt-0.5">
                {anomalies.length === data.anomalies.length
                  ? `${data.anomalies.length} item(s) flagged by Claude AI`
                  : `Showing ${anomalies.length} of ${data.anomalies.length} flagged item(s)`}
              </p>
            </div>

            {/* Filter and sort controls — only useful once there's more than one row */}
            {data.anomalies.length > 1 && (
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter by user, URL, reason…"
                  className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-1.5 text-gray-200 placeholder-gray-600 w-56 focus:outline-none focus:border-blue-600"
                />
                <label className="flex items-center gap-1.5 text-gray-500">
                  Severity
                  <select
                    value={minBand}
                    onChange={(e) => setMinBand(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-lg px-2 py-1.5 text-gray-200 focus:outline-none focus:border-blue-600"
                  >
                    <option value="All">All</option>
                    <option value="Medium">Medium &amp; up</option>
                    <option value="High">High only</option>
                  </select>
                </label>
                <label className="flex items-center gap-1.5 text-gray-500">
                  Sort
                  <select
                    value={sortKey}
                    onChange={(e) => setSortKey(e.target.value as SortKey)}
                    className="bg-gray-950 border border-gray-800 rounded-lg px-2 py-1.5 text-gray-200 focus:outline-none focus:border-blue-600"
                  >
                    <option value="confidence">Confidence</option>
                    <option value="user">User</option>
                    <option value="timestamp">Time</option>
                  </select>
                </label>
              </div>
            )}
          </div>

          {data.anomalies.length === 0 ? (
            <p className="px-5 py-6 text-gray-500 text-sm">No anomalies detected. Traffic appears normal.</p>
          ) : anomalies.length === 0 ? (
            <p className="px-5 py-6 text-gray-500 text-sm">No anomalies match the current filter.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="px-5 py-3 text-left font-medium">Timestamp</th>
                    <th className="px-5 py-3 text-left font-medium">User</th>
                    <th className="px-5 py-3 text-left font-medium">URL</th>
                    <th className="px-5 py-3 text-left font-medium">Reason</th>
                    <th className="px-5 py-3 text-left font-medium">ATT&amp;CK</th>
                    <th className="px-5 py-3 text-left font-medium">Severity</th>
                    <th className="px-5 py-3 text-left font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.map((a, i) => (
                    // Each row has a subtle red background to flag it as suspicious
                    <tr key={`${a.timestamp}-${a.url}-${i}`} className="border-b border-gray-800/40 bg-red-950/10 hover:bg-red-950/20 transition-colors">
                      <td className="px-5 py-3 text-gray-500 whitespace-nowrap">{a.timestamp}</td>
                      <td className="px-5 py-3 text-gray-300">{a.user}</td>
                      <td className="px-5 py-3 text-blue-400 max-w-xs truncate">{a.url}</td>
                      <td className="px-5 py-3 text-gray-300 max-w-sm">{a.reason}</td>
                      {/* Technique IDs, with the full name on hover */}
                      <td className="px-5 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(a.attack_techniques ?? []).length > 0
                            ? a.attack_techniques!.map((t) => (
                                <span
                                  key={t.id}
                                  title={t.name}
                                  className="px-1.5 py-0.5 rounded bg-purple-950/60 border border-purple-900 text-purple-300 font-mono whitespace-nowrap"
                                >
                                  {t.id}
                                </span>
                              ))
                            : <span className="text-gray-700">&mdash;</span>}
                        </div>
                      </td>
                      <td className={`px-5 py-3 font-semibold ${bandColor(a.confidence)}`}>{band(a.confidence)}</td>
                      <td className={`px-5 py-3 font-bold ${bandColor(a.confidence)}`}>
                        {(a.confidence * 100).toFixed(0)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ---- Section 5: SOC Recommendations ----
            Claude's own next steps, stored with the report.               */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-5">
          <h2 className="font-semibold text-gray-200 mb-4">SOC Recommendations</h2>
          {data.recommendations.length > 0 ? (
            <ul className="space-y-2.5">
              {data.recommendations.map((rec, i) => (
                <li key={i} className="flex gap-3 text-sm text-gray-300">
                  <span className="text-blue-400 shrink-0 font-bold">&rarr;</span>
                  {rec}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-gray-500 text-sm">No recommendations were returned for this log.</p>
          )}
        </div>

        {/* ---- Section 6: Detection Rules ----
            Closes the loop: not just "you were attacked", but the Sigma rule
            that catches it next time. Only rendered when Claude wrote some. */}
        {!!data.detections?.length && (
          <div className="bg-gray-900 rounded-xl border border-gray-800">
            <div className="px-5 py-4 border-b border-gray-800">
              <h2 className="font-semibold text-gray-200">Detection Rules</h2>
              <p className="text-xs text-gray-500 mt-0.5">
                {data.detections.length} Sigma rule(s) — deployable to your SIEM
              </p>
            </div>
            <div className="divide-y divide-gray-800/60">
              {data.detections.map((d, i) => (
                <DetectionCard key={`${d.title}-${i}`} rule={d} />
              ))}
            </div>
          </div>
        )}

      </main>
    </div>
  )
}

// -----------------------------------------------------------------------
// DetectionCard — one Sigma rule, collapsed by default
//
// The YAML is the useful part but it's long, so the list stays scannable by
// title and only expands what the analyst asks for.
// -----------------------------------------------------------------------

const RULE_SEVERITY: Record<string, string> = {
  critical: 'bg-red-950 text-red-400 border-red-900',
  high: 'bg-orange-950 text-orange-400 border-orange-900',
  medium: 'bg-yellow-950 text-yellow-400 border-yellow-900',
  low: 'bg-green-950 text-green-400 border-green-900',
}

function DetectionCard({ rule }: { rule: DetectionRule }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(rule.sigma)
      setCopied(true)
      timer.current = setTimeout(() => setCopied(false), 2000)
    } catch {
      alert('Could not access the clipboard. Expand the rule and copy it manually.')
    }
  }, [rule.sigma])

  const severity = rule.severity?.toLowerCase() ?? ''

  return (
    <div className="px-5 py-4">
      <div className="flex items-start justify-between gap-3">
        <button onClick={() => setOpen((v) => !v)} className="text-left min-w-0 group">
          <div className="flex items-center gap-2">
            <span className="text-gray-600 text-xs w-3 shrink-0">{open ? '▾' : '▸'}</span>
            <span className="text-sm text-gray-200 group-hover:text-white transition-colors">{rule.title}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full border shrink-0 ${RULE_SEVERITY[severity] ?? 'bg-gray-800 text-gray-400 border-gray-700'}`}>
              {rule.severity}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1 ml-5">{rule.description}</p>
        </button>
        <button
          onClick={copy}
          className="text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors shrink-0"
        >
          {copied ? 'Copied' : 'Copy rule'}
        </button>
      </div>

      {open && (
        <pre className="mt-3 ml-5 p-3 bg-gray-950 border border-gray-800 rounded-lg overflow-x-auto text-xs text-gray-300 font-mono">
          {rule.sigma}
        </pre>
      )}
    </div>
  )
}

// -----------------------------------------------------------------------
// ExportButtons — get the report out of the browser and into a ticket
// -----------------------------------------------------------------------

function ExportButtons({ data }: { data: Result }) {
  const [copied, setCopied] = useState(false)

  // Clear the "Copied" label after a moment, and cancel that timer if the
  // component unmounts first
  const resetTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => { if (resetTimer.current) clearTimeout(resetTimer.current) }, [])

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(toMarkdown(data))
      setCopied(true)
      resetTimer.current = setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard access can be refused (permissions, insecure origin).
      // Downloading still works, so point the user at that instead.
      alert('Could not access the clipboard. Use "Download" instead.')
    }
  }, [data])

  const download = useCallback(() => {
    const blob = new Blob([toMarkdown(data)], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${data.filename.replace(/\.(log|txt)$/i, '')}-soc-report.md`
    a.click()
    URL.revokeObjectURL(url)
  }, [data])

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={copy}
        className="text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
      >
        {copied ? 'Copied' : 'Copy as Markdown'}
      </button>
      <button
        onClick={download}
        className="text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
      >
        Download
      </button>
    </div>
  )
}
