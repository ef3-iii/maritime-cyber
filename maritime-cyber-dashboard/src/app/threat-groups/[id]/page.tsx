import { getSupabaseServer } from '@/lib/supabase'
import { notFound } from 'next/navigation'
import Link from 'next/link'

export default async function ThreatGroupDetail({ params }: { params: { id: string } }) {
  const supabase = getSupabaseServer()
  const { data: group } = await supabase.from('threat_groups').select('*').eq('id', params.id).single()
  if (!group) notFound()

  const ttps: string[] = group.ttps ?? []

  return (
    <main className="min-h-screen bg-gray-950 text-white p-6">
      <Link href="/" className="text-gray-400 hover:text-white text-sm mb-6 inline-block">← Back to dashboard</Link>

      <div className="max-w-3xl">
        <div className="flex items-center gap-4 mb-6">
          <h1 className="text-2xl font-bold">{group.name}</h1>
          <span className={`px-3 py-1 rounded text-sm font-semibold ${group.active ? 'bg-red-600 text-white' : 'bg-gray-600 text-gray-300'}`}>
            {group.active ? 'Active' : 'Inactive'}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-6">
          {[
            ['Confirmed Victims', group.victim_count.toString()],
            ['Last Activity', new Date(group.last_activity).toLocaleDateString()],
            ['TTPs', ttps.length.toString()],
            ['First Recorded', new Date(group.created_at).toLocaleString()],
          ].map(([label, value]) => (
            <div key={label} className="bg-gray-900 rounded-lg p-4">
              <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">{label}</div>
              <div className="font-semibold text-lg">{value}</div>
            </div>
          ))}
        </div>

        {group.description && (
          <div className="bg-gray-900 rounded-lg p-4 mb-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">Description</div>
            <p className="text-gray-200 leading-relaxed">{group.description}</p>
          </div>
        )}

        {ttps.length > 0 && (
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">Tactics, Techniques & Procedures</div>
            <div className="flex flex-wrap gap-2">
              {ttps.map((ttp) => (
                <span key={ttp} className="bg-orange-900/50 text-orange-300 border border-orange-700 px-3 py-1 rounded text-sm">
                  {ttp}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </main>
  )
}
