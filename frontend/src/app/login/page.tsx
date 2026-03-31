// -----------------------------------------------------------------------
// app/login/page.tsx — Login & Register page
//
// This is the first page a user sees. It handles two things:
//   1. Logging in with an existing account
//   2. Registering a brand new account
//
// The user toggles between the two modes with the Sign In / Register tabs.
// On success, the JWT token is saved to localStorage so future API calls
// can include it, and the user is sent to /upload.
// -----------------------------------------------------------------------

'use client' // This page uses React state and event handlers, so it must run in the browser

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { login, register } from '@/lib/api' // Our backend API helper functions

export default function LoginPage() {
  const router = useRouter() // Used to navigate to /upload after login

  // Controls which tab is active: 'login' or 'register'
  const [mode, setMode] = useState<'login' | 'register'>('login')

  // The values the user types into the form fields
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  // Shows a spinner on the button while waiting for the server
  const [loading, setLoading] = useState(false)

  // Displays an error message below the form if something goes wrong
  const [error, setError] = useState('')

  // Runs when the user clicks "Sign In" or "Create Account"
  const handleSubmit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault() // Stop the browser from doing a full page reload
    setLoading(true)
    setError('')

    try {
      // If registering, create the account first
      if (mode === 'register') {
        await register(username, password)
      }

      // Log in (works for both new and existing accounts)
      const data = await login(username, password)

      // Save the JWT token so every future API request can authenticate
      // The token is read by api.ts and attached to request headers automatically
      localStorage.setItem('token', data.token)

      // Send the user to the upload page
      router.push('/upload')

    } catch (err: unknown) {
      // Pull the error message out of the axios response if available
      const e = err as { response?: { data?: { detail?: string } } }
      setError(e.response?.data?.detail || 'Something went wrong. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
      <div className="w-full max-w-sm">

        {/* App title / branding at the top */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-white">TENEX SOC Analyzer</h1>
          <p className="text-gray-500 text-sm mt-2">AI-powered ZScaler log analysis</p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">

          {/* Tab switcher — clicking these changes the mode between login/register */}
          <div className="flex rounded-xl bg-gray-800 p-1 mb-6">
            <button
              onClick={() => { setMode('login'); setError('') }}
              className={`flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${mode === 'login' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setMode('register'); setError('') }}
              className={`flex-1 py-2 text-sm font-medium rounded-lg transition-colors ${mode === 'register' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              Register
            </button>
          </div>

          {/* The form — same fields for both login and register */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)} // Update state as user types
                required
                className="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="your username"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)} // Update state as user types
                required
                className="w-full bg-gray-800 border border-gray-700 text-white rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="••••••••"
              />
            </div>

            {/* Only shows if there's an error (e.g. wrong password) */}
            {error && <p className="text-red-400 text-xs">{error}</p>}

            {/* Button label changes based on mode and loading state */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors text-sm mt-2"
            >
              {loading ? 'Please wait...' : mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>

        </div>
      </div>
    </div>
  )
}
