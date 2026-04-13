'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { getSupabaseBrowser } from '@/lib/supabase-browser'
import Link from 'next/link'

export default function AccountPage() {
  const router = useRouter()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    if (password !== confirm) {
      setStatus('error')
      setMessage('Passwords do not match.')
      return
    }
    if (password.length < 8) {
      setStatus('error')
      setMessage('Password must be at least 8 characters.')
      return
    }
    setLoading(true)
    setStatus('idle')

    const supabase = getSupabaseBrowser()
    const { error } = await supabase.auth.updateUser({ password })

    if (error) {
      setStatus('error')
      setMessage(error.message)
    } else {
      setStatus('success')
      setMessage('Password updated successfully.')
      setPassword('')
      setConfirm('')
    }
    setLoading(false)
  }

  return (
    <main className="min-h-screen bg-gray-950 text-white p-6">
      <Link href="/" className="text-gray-400 hover:text-white text-sm mb-6 inline-block">
        ← Back to dashboard
      </Link>

      <div className="max-w-sm">
        <h1 className="text-2xl font-bold mb-6">Account Settings</h1>

        <form onSubmit={handleChangePassword} className="bg-gray-900 rounded-lg p-6 space-y-4">
          <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">Change Password</div>

          <div>
            <label className="block text-gray-400 text-xs uppercase tracking-wide mb-1">New Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-gray-800 text-white rounded px-3 py-2 text-sm border border-gray-700 focus:border-blue-500 focus:outline-none"
              placeholder="Min. 8 characters"
            />
          </div>

          <div>
            <label className="block text-gray-400 text-xs uppercase tracking-wide mb-1">Confirm Password</label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              className="w-full bg-gray-800 text-white rounded px-3 py-2 text-sm border border-gray-700 focus:border-blue-500 focus:outline-none"
              placeholder="Repeat new password"
            />
          </div>

          {status === 'error' && (
            <div className="bg-red-900/40 border border-red-700 text-red-300 text-sm rounded px-3 py-2">
              {message}
            </div>
          )}
          {status === 'success' && (
            <div className="bg-green-900/40 border border-green-700 text-green-300 text-sm rounded px-3 py-2">
              {message}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-900 disabled:text-blue-400 text-white font-semibold py-2 rounded text-sm transition-colors"
          >
            {loading ? 'Updating…' : 'Update Password'}
          </button>
        </form>
      </div>
    </main>
  )
}
