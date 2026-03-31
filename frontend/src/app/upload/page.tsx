// -----------------------------------------------------------------------
// app/upload/page.tsx — File Upload page
//
// This page lets the user pick a ZScaler log file to analyze.
// It supports two ways to select a file:
//   1. Drag and drop onto the dashed box
//   2. Click the box to open a file browser
//
// Once the user clicks "Upload & Analyze", the file is sent to the backend.
// The backend saves it and returns an upload_id, which we pass to /dashboard
// so the dashboard knows which file to analyze.
// -----------------------------------------------------------------------

'use client' // Needs browser APIs (drag events, file input, localStorage)

import { useState, useCallback, useRef, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { uploadFile } from '@/lib/api' // Sends the file to POST /api/upload

export default function UploadPage() {
  const router = useRouter()

  // A ref lets us programmatically click the hidden file input when the box is clicked
  const inputRef = useRef<HTMLInputElement>(null)

  // True while the user is dragging a file over the drop zone (changes border color)
  const [dragging, setDragging] = useState(false)

  // The file the user has selected (either via drag-drop or file browser)
  const [file, setFile] = useState<File | null>(null)

  // True while waiting for the backend to respond to the upload request
  const [uploading, setUploading] = useState(false)

  // Error message shown below the drop zone if something goes wrong
  const [error, setError] = useState('')

  // Guard: if there's no JWT token in localStorage, the user isn't logged in
  // Send them back to /login before they can see this page
  useEffect(() => {
    if (!localStorage.getItem('token')) router.push('/login')
  }, [router])

  // Runs when the user drops a file onto the drop zone
  // useCallback prevents this function from being recreated on every render
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()       // Stop the browser from opening the file
    setDragging(false)        // Remove the blue highlight
    const f = e.dataTransfer.files[0] // Grab the first dropped file
    if (f) setFile(f)
  }, [])

  // Runs when the user clicks the "Upload & Analyze" button
  const handleUpload = async () => {
    if (!file) return // Nothing to upload
    setUploading(true)
    setError('')

    try {
      // Send the file to the backend — returns { upload_id, filename, status }
      const data = await uploadFile(file)

      // Navigate to the dashboard and pass the upload ID as a URL query param
      // The dashboard reads upload_id from the URL to know what to analyze
      router.push(`/dashboard?upload_id=${data.upload_id}`)

    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } } }
      setError(err.response?.data?.detail || 'Upload failed. Please try again.')
      setUploading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center p-8">
      <div className="w-full max-w-lg">

        {/* Page header */}
        <div className="text-center mb-10">
          <h1 className="text-3xl font-bold text-white">TENEX SOC Analyzer</h1>
          <p className="text-gray-400 mt-2 text-sm">
            Upload a ZScaler web proxy log for AI-powered threat detection
          </p>
        </div>

        {/* Drop zone — the big dashed box
            Border color changes based on state:
              - Blue when dragging a file over it
              - Green when a file has been selected
              - Gray (default) otherwise                    */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()} // Clicking the box opens the file picker
          className={`border-2 border-dashed rounded-2xl p-14 text-center cursor-pointer transition-all ${
            dragging
              ? 'border-blue-500 bg-blue-950/20'   // Dragging over
              : file
              ? 'border-green-600 bg-green-950/10'  // File selected
              : 'border-gray-700 bg-gray-900 hover:border-gray-600 hover:bg-gray-900/80' // Default
          }`}
        >
          {/* Hidden file input — triggered by clicking the drop zone */}
          <input
            ref={inputRef}
            type="file"
            accept=".log,.txt"    // Only allow log and text files
            className="hidden"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />

          {/* Show file name once selected, otherwise show the upload icon + instructions */}
          {file ? (
            <div>
              <p className="text-green-400 font-semibold text-lg">{file.name}</p>
              <p className="text-gray-500 text-sm mt-1">
                {(file.size / 1024).toFixed(1)} KB &middot; Click to change
              </p>
            </div>
          ) : (
            <div>
              {/* Upload icon */}
              <div className="w-14 h-14 mx-auto mb-4 rounded-full bg-gray-800 flex items-center justify-center">
                <svg className="w-7 h-7 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                    d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
              </div>
              <p className="text-gray-300 font-medium">Drop your log file here</p>
              <p className="text-gray-500 text-sm mt-1">or click to browse</p>
              <p className="text-gray-600 text-xs mt-3">Supports .log and .txt files</p>
            </div>
          )}
        </div>

        {/* Error message — only visible if upload fails */}
        {error && <p className="mt-3 text-red-400 text-sm text-center">{error}</p>}

        {/* Upload button — disabled until a file is selected or while uploading */}
        <button
          onClick={handleUpload}
          disabled={!file || uploading}
          className="w-full mt-5 py-3.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors text-sm"
        >
          {uploading ? 'Uploading...' : 'Upload & Analyze with Claude AI'}
        </button>

        {/* Hint box pointing users to the sample log files */}
        <div className="mt-6 bg-gray-900 border border-gray-800 rounded-xl p-4">
          <p className="text-xs text-gray-500 font-medium mb-2">Sample log files included in the project:</p>
          <div className="space-y-1 text-xs text-gray-600">
            <p><span className="text-gray-400">normal_traffic.log</span> — routine web proxy activity, low risk</p>
            <p><span className="text-gray-400">incident_scenario.log</span> — simulated incident with malware and C2 traffic</p>
          </div>
        </div>

      </div>
    </div>
  )
}
