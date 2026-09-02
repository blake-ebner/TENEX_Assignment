// -----------------------------------------------------------------------
// app/history/page.tsx — "My Analyses"
//
// Every upload a user has ever made, newest first. Without this page the
// upload_id only exists in the dashboard URL, so closing the tab loses the
// report even though the backend has kept it.
//
// Reports are stored, not re-run: clicking a finished analysis opens the
// saved result. Clicking one that failed or never started opens the
// dashboard, which starts (or retries) the analysis.
// -----------------------------------------------------------------------

'use client' // Uses hooks and localStorage, so must run in the browser

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { getUploads } from '@/lib/api' // Calls GET /api/uploads

// One row of GET /api/uploads
interface UploadItem {
  upload_id: string
  filename: string
  status: string      // pending | queued | analyzing | done | error
  uploaded_at: string
}

// Badge styling per status. Anything unexpected falls back to neutral gray.
const statusStyle = (s: string) =>
  ({
    done:      'bg-green-950 text-green-400 border-green-900',
    analyzing: 'bg-blue-950 text-blue-400 border-blue-900',
    queued:    'bg-blue-950 text-blue-400 border-blue-900',
    pending:   'bg-gray-800 text-gray-400 border-gray-700',
    error:     'bg-red-950 text-red-400 border-red-900',
  }[s] ?? 'bg-gray-800 text-gray-400 border-gray-700')

// "done" is the only status where a report already exists; the rest tell the
// user what will happen when they click the row.
const statusLabel = (s: string) =>
  ({
    done: 'Report ready',
    analyzing: 'Analyzing',
    queued: 'Queued',
    pending: 'Not analyzed',
    error: 'Failed',
  }[s] ?? s)

export default function HistoryPage() {
  const router = useRouter()

  const [uploads, setUploads] = useState<UploadItem[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    // Guard: no token means the user isn't logged in
    if (!localStorage.getItem('token')) { router.push('/login'); return }

    getUploads()
      .then(setUploads)
      .catch((e: unknown) => {
        const err = e as { response?: { data?: { detail?: string } } }
        setError(err.response?.data?.detail || 'Could not load your analyses.')
        setUploads([])
      })
  }, [router])

  return (
    <div className="min-h-screen bg-gray-950 text-white">

      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 className="text-lg font-bold text-blue-400">My Analyses</h1>
          <p className="text-xs text-gray-500">
            {uploads ? `${uploads.length} log file(s) uploaded` : 'Loading…'}
          </p>
        </div>
        <div className="flex items-center gap-4 shrink-0">
          <button
            onClick={() => router.push('/trends')}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            Trends
          </button>
          <button
            onClick={() => router.push('/upload')}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            + New Analysis
          </button>
        </div>
      </header>

      <main className="max-w-4xl mx-auto p-6">
        {error && <p className="mb-4 text-red-400 text-sm">{error}</p>}

        {/* Loading — the list is a single request, so a plain line is enough */}
        {!uploads && !error && (
          <p className="text-gray-500 text-sm">Loading your analyses&hellip;</p>
        )}

        {/* Empty state — send the user somewhere useful rather than a blank page */}
        {uploads && uploads.length === 0 && !error && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center">
            <p className="text-gray-300">You haven&apos;t analyzed any logs yet.</p>
            <button
              onClick={() => router.push('/upload')}
              className="mt-4 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm transition-colors"
            >
              Upload a log file
            </button>
          </div>
        )}

        {/* The list itself */}
        {uploads && uploads.length > 0 && (
          <div className="bg-gray-900 rounded-xl border border-gray-800 divide-y divide-gray-800/60">
            {uploads.map((u) => (
              <button
                key={u.upload_id}
                onClick={() => router.push(`/dashboard?upload_id=${u.upload_id}`)}
                className="w-full text-left px-5 py-4 flex items-center justify-between gap-4 hover:bg-gray-800/40 transition-colors first:rounded-t-xl last:rounded-b-xl"
              >
                <div className="min-w-0">
                  <p className="text-sm text-gray-200 truncate">{u.filename}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {new Date(u.uploaded_at).toLocaleString()}
                  </p>
                </div>
                <span className={`text-xs px-2.5 py-1 rounded-full border shrink-0 ${statusStyle(u.status)}`}>
                  {statusLabel(u.status)}
                </span>
              </button>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
