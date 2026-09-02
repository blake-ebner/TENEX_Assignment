// -----------------------------------------------------------------------
// app/trends/page.tsx — Cross-upload trends
//
// Every other page in this app looks at one log file. This one looks across
// all of them, because the interesting question isn't "was this file bad" but
// "is this the fourth week running that the same account got flagged".
//
// Data comes from GET /api/trends, which rolls up every completed analysis
// the user owns (see backend/trends.py).
// -----------------------------------------------------------------------

'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { getTrends } from '@/lib/api'

interface FlaggedUser {
  user: string
  report_count: number   // how many separate reports flagged them
  anomaly_count: number  // total anomalies across all reports
  max_confidence: number
  first_seen: string
  last_seen: string
  filenames: string[]
}

interface RecurringTechnique {
  id: string
  name: string
  report_count: number
  anomaly_count: number
}

interface ReportSummary {
  upload_id: string
  filename: string
  created_at: string
  risk_level: string
  anomaly_count: number
}

interface Trends {
  report_count: number
  reports: ReportSummary[]
  flagged_users: FlaggedUser[]
  recurring_techniques: RecurringTechnique[]
}

const riskBg = (r: string) =>
  ({ Critical: 'bg-red-600', High: 'bg-orange-500', Medium: 'bg-yellow-500', Low: 'bg-green-600' }[r] ?? 'bg-gray-600')

export default function TrendsPage() {
  const router = useRouter()

  const [data, setData] = useState<Trends | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!localStorage.getItem('token')) { router.push('/login'); return }

    getTrends()
      .then(setData)
      .catch((e: unknown) => {
        const err = e as { response?: { data?: { detail?: string } } }
        setError(err.response?.data?.detail || 'Could not load trends.')
      })
  }, [router])

  return (
    <div className="min-h-screen bg-gray-950 text-white">

      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between gap-4 sticky top-0 z-10">
        <div>
          <h1 className="text-lg font-bold text-blue-400">Trends</h1>
          <p className="text-xs text-gray-500">
            {data ? `Across ${data.report_count} completed analysis(es)` : 'Loading…'}
          </p>
        </div>
        <div className="flex items-center gap-4 shrink-0">
          <button onClick={() => router.push('/history')} className="text-sm text-gray-400 hover:text-white transition-colors">
            My Analyses
          </button>
          <button onClick={() => router.push('/upload')} className="text-sm text-gray-400 hover:text-white transition-colors">
            + New Analysis
          </button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto p-6 space-y-5">
        {error && <p className="text-red-400 text-sm">{error}</p>}
        {!data && !error && <p className="text-gray-500 text-sm">Loading trends&hellip;</p>}

        {/* Trends need history to be meaningful — say so rather than showing
            three empty panels. */}
        {data && data.report_count < 2 && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center">
            <p className="text-gray-300">
              {data.report_count === 0
                ? 'No completed analyses yet.'
                : 'Only one analysis so far.'}
            </p>
            <p className="text-gray-500 text-sm mt-2">
              Trends compare findings across uploads — analyze at least two log files
              and patterns will show up here.
            </p>
            <button
              onClick={() => router.push('/upload')}
              className="mt-4 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm transition-colors"
            >
              Upload another log
            </button>
          </div>
        )}

        {data && data.report_count >= 2 && (
          <>
            {/* ---- Repeat offenders ---- */}
            <div className="bg-gray-900 rounded-xl border border-gray-800">
              <div className="px-5 py-4 border-b border-gray-800">
                <h2 className="font-semibold text-gray-200">Repeat Offenders</h2>
                <p className="text-xs text-gray-500 mt-0.5">
                  Users ranked by how many separate reports flagged them — persistence
                  matters more than volume in any single file
                </p>
              </div>
              {data.flagged_users.length ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-gray-800 text-gray-500">
                        <th className="px-5 py-3 text-left font-medium">User</th>
                        <th className="px-5 py-3 text-left font-medium">Reports</th>
                        <th className="px-5 py-3 text-left font-medium">Anomalies</th>
                        <th className="px-5 py-3 text-left font-medium">Peak confidence</th>
                        <th className="px-5 py-3 text-left font-medium">First seen</th>
                        <th className="px-5 py-3 text-left font-medium">Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.flagged_users.map((u) => {
                        const repeat = u.report_count > 1
                        return (
                          <tr
                            key={u.user}
                            className={`border-b border-gray-800/40 transition-colors ${
                              repeat ? 'bg-red-950/10 hover:bg-red-950/20' : 'hover:bg-gray-800/30'
                            }`}
                          >
                            <td className="px-5 py-3 text-gray-200">{u.user}</td>
                            <td className="px-5 py-3">
                              {/* The headline number: a user in many reports is a pattern */}
                              <span
                                className={repeat ? 'text-red-400 font-bold' : 'text-gray-400'}
                                title={u.filenames.join(', ')}
                              >
                                {u.report_count} of {data.report_count}
                              </span>
                            </td>
                            <td className="px-5 py-3 text-gray-400">{u.anomaly_count}</td>
                            <td className="px-5 py-3 text-gray-400">
                              {(u.max_confidence * 100).toFixed(0)}%
                            </td>
                            <td className="px-5 py-3 text-gray-600 whitespace-nowrap">
                              {new Date(u.first_seen).toLocaleDateString()}
                            </td>
                            <td className="px-5 py-3 text-gray-600 whitespace-nowrap">
                              {new Date(u.last_seen).toLocaleDateString()}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="px-5 py-6 text-gray-500 text-sm">
                  No users have been flagged in any report yet.
                </p>
              )}
            </div>

            {/* ---- Recurring ATT&CK techniques ---- */}
            <div className="bg-gray-900 rounded-xl border border-gray-800">
              <div className="px-5 py-4 border-b border-gray-800">
                <h2 className="font-semibold text-gray-200">Recurring ATT&amp;CK Techniques</h2>
                <p className="text-xs text-gray-500 mt-0.5">
                  Adversary behaviour that keeps reappearing — a technique seen in most
                  of your reports is a gap in controls, not a one-off
                </p>
              </div>
              {data.recurring_techniques.length ? (
                <div className="divide-y divide-gray-800/60">
                  {data.recurring_techniques.map((t) => (
                    <div key={t.id} className="px-5 py-3 flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="px-1.5 py-0.5 rounded bg-purple-950/60 border border-purple-900 text-purple-300 font-mono text-xs shrink-0">
                          {t.id}
                        </span>
                        <span className="text-sm text-gray-300 truncate">{t.name}</span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        {/* Proportion bar: how much of your history this technique spans */}
                        <div className="w-28 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-purple-500"
                            style={{ width: `${(t.report_count / data.report_count) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs text-gray-500 w-24 text-right">
                          {t.report_count} of {data.report_count} reports
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="px-5 py-6 text-gray-500 text-sm">
                  No ATT&amp;CK techniques recorded yet. Reports generated before technique
                  mapping was added won&apos;t contribute here — re-run one to populate it.
                </p>
              )}
            </div>

            {/* ---- Risk over time ---- */}
            <div className="bg-gray-900 rounded-xl border border-gray-800">
              <div className="px-5 py-4 border-b border-gray-800">
                <h2 className="font-semibold text-gray-200">Risk Over Time</h2>
                <p className="text-xs text-gray-500 mt-0.5">Every completed analysis, oldest first</p>
              </div>
              <div className="divide-y divide-gray-800/60">
                {data.reports.map((r) => (
                  <button
                    key={r.upload_id}
                    onClick={() => router.push(`/dashboard?upload_id=${r.upload_id}`)}
                    className="w-full text-left px-5 py-3 flex items-center justify-between gap-4 hover:bg-gray-800/40 transition-colors"
                  >
                    <div className="min-w-0">
                      <p className="text-sm text-gray-200 truncate">{r.filename}</p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {new Date(r.created_at).toLocaleString()} &middot; {r.anomaly_count} anomalies
                      </p>
                    </div>
                    <span className={`text-xs px-3 py-1 rounded-full text-white font-semibold shrink-0 ${riskBg(r.risk_level)}`}>
                      {r.risk_level}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  )
}
