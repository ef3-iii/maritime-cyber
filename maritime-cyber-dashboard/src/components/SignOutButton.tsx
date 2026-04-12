'use client'

import { useRouter } from 'next/navigation'
import { getSupabaseBrowser } from '@/lib/supabase-browser'

export default function SignOutButton() {
  const router = useRouter()

  async function handleSignOut() {
    const supabase = getSupabaseBrowser()
    await supabase.auth.signOut()
    router.push('/login')
    router.refresh()
  }

  return (
    <button
      onClick={handleSignOut}
      className="text-sm text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 px-3 py-1.5 rounded transition-colors"
    >
      Sign out
    </button>
  )
}
