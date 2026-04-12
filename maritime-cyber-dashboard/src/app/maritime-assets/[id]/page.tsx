import { getSupabaseServer } from '@/lib/supabase'
import { notFound } from 'next/navigation'
import Link from 'next/link'

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-yellow-500 text-black',
  Low: 'bg-blue-500 text-white',
}

const EXPOSURE_COLOR = (score: number) => {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-yellow-400'
  return 'text-green-400'
}

export default async function AssetDetail({ params }: { params: { id: string } }) {
  const supabase = getSupabaseServer()
  const { data: asset } = await supabase.from('maritime_assets').select('*').eq('id', params.id).single()
  if (!asset) notFound()

  const vulns: { cve_id: string; severity: string; description: string }[] = asset.vulnerabilities ?? []

  return (
    <main className="min-h-screen bg-gray-950 text-white p-6">
      <Link href="/" className="text-gray-400 hover:text-white text-sm mb-6 inline-block">← Back to dashboard</Link>

      <div className="max-w-3xl">
        <h1 className="text-2xl font-bold mb-6">{asset.name}</h1>

        <div className="grid grid-cols-2 gap-4 mb-6">
          {[
            ['Asset Type', asset.asset_type],
            ['Country', asset.country ?? '—'],
            ['Recorded', new Date(asset.created_at).toLocaleString()],
          ].map(([label, value]) => (
            <div key={label} className="bg-gray-900 rounded-lg p-4">
              <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">{label}</div>
              <div className="font-medium">{value}</div>
            </div>
          ))}
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">Exposure Score</div>
            <div className={`text-3xl font-bold ${EXPOSURE_COLOR(asset.exposure_score)}`}>
              {asset.exposure_score}<span className="text-gray-600 text-base font-normal"> / 100</span>
            </div>
          </div>
        </div>

        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">
            Vulnerabilities ({vulns.length})
          </div>
          {vulns.length === 0 ? (
            <p className="text-gray-500 text-sm">No vulnerabilities recorded.</p>
          ) : (
            <div className="space-y-3">
              {vulns.map((v) => (
                <div key={v.cve_id} className="bg-gray-800 rounded p-3 flex items-start gap-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold whitespace-nowrap ${SEVERITY_COLOR[v.severity] ?? 'bg-gray-600 text-white'}`}>
                    {v.severity}
                  </span>
                  <div>
                    <div className="font-mono text-sm text-blue-400">{v.cve_id}</div>
                    <div className="text-gray-300 text-sm mt-0.5">{v.description}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </main>
  )
}
