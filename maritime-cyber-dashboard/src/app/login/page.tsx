'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { getSupabaseBrowser } from '@/lib/supabase-browser'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)

    const supabase = getSupabaseBrowser()
    const { error } = await supabase.auth.signInWithPassword({ email, password })

    if (error) {
      setError(error.message)
      setLoading(false)
    } else {
      router.push('/')
      router.refresh()
    }
  }

  return (
    <main className="min-h-screen bg-gray-950 flex items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-white">Maritime Cyber Dashboard</h1>
          <p className="text-gray-400 text-sm mt-1">MTS-OPS-CENTER</p>
        </div>

        <form onSubmit={handleLogin} className="bg-gray-900 rounded-lg p-6 space-y-4">
          <div>
            <label className="block text-gray-400 text-xs uppercase tracking-wide mb-1">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full bg-gray-800 text-white rounded px-3 py-2 text-sm border border-gray-700 focus:border-blue-500 focus:outline-none"
              placeholder="analyst@example.com"
            />
          </div>

          <div>
            <label className="block text-gray-400 text-xs uppercase tracking-wide mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-gray-800 text-white rounded px-3 py-2 text-sm border border-gray-700 focus:border-blue-500 focus:outline-none"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <div className="bg-red-900/40 border border-red-700 text-red-300 text-sm rounded px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-900 disabled:text-blue-400 text-white font-semibold py-2 rounded text-sm transition-colors"
          >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </main>
  )
}
