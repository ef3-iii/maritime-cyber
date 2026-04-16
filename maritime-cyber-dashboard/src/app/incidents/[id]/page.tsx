import { getSupabaseServer } from '@/lib/supabase'
import { notFound } from 'next/navigation'
import Link from 'next/link'
import RelationshipEditor from '@/components/RelationshipEditor'
import EnrichButton from '@/components/EnrichButton'

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-yellow-500 text-black',
  Low: 'bg-blue-500 text-white',
}

export default async function IncidentDetail({ params }: { params: { id: string } }) {
  const supabase = getSupabaseServer()

  const [{ data: inc }, { data: threatGroups }, { data: assets }] = await Promise.all([
    supabase.from('incidents').select('*, threat_groups(id,name), maritime_assets(id,name)').eq('id', params.id).single(),
    supabase.from('threat_groups').select('id, name').order('name'),
    supabase.from('maritime_assets').select('id, name').order('name'),
  ])

  if (!inc) notFound()

  const linkedThreatGroup = inc.threat_groups as { id: string; name: string } | null
  const linkedAsset = inc.maritime_assets as { id: string; name: string } | null

  return (
    <main className="min-h-screen bg-gray-950 text-white p-6">
      <Link href="/" className="text-gray-400 hover:text-white text-sm mb-6 inline-block">← Back to dashboard</Link>

      <div className="max-w-3xl">
        <div className="flex items-start gap-4 mb-6">
          <h1 className="text-2xl font-bold flex-1">{inc.title}</h1>
          <span className={`px-3 py-1 rounded font-semibold text-sm whitespace-nowrap ${SEVERITY_COLOR[inc.severity] ?? 'bg-gray-600 text-white'}`}>
            {inc.severity}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-6">
          {[
            ['Sector', inc.sector],
            ['Attack Vector', inc.attack_vector],
            ['Target Organization', inc.target_organization ?? '—'],
            ['Target Country', inc.target_country ?? '—'],
            ['Recorded', new Date(inc.created_at).toLocaleString()],
          ].map(([label, value]) => (
            <div key={label} className="bg-gray-900 rounded-lg p-4">
              <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">{label}</div>
              <div className="font-medium">{value}</div>
            </div>
          ))}
        </div>

        {/* Relationship editors */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          <RelationshipEditor
            incidentId={inc.id}
            field="threat_group_id"
            label="Linked Threat Group"
            options={threatGroups ?? []}
            currentId={inc.threat_group_id ?? null}
            currentName={linkedThreatGroup?.name ?? null}
          />
          <RelationshipEditor
            incidentId={inc.id}
            field="maritime_asset_id"
            label="Linked Asset"
            options={(assets ?? []).map(a => ({ id: a.id, name: a.name }))}
            currentId={inc.maritime_asset_id ?? null}
            currentName={linkedAsset?.name ?? null}
          />
        </div>

        {inc.description && (
          <div className="bg-gray-900 rounded-lg p-4 mb-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">Description</div>
            <p className="text-gray-200 leading-relaxed">{inc.description}</p>
          </div>
        )}

        {inc.iocs && (
          <div className="bg-gray-900 rounded-lg p-4 mb-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">Indicators of Compromise</div>
            {Object.entries(inc.iocs as Record<string, string[]>).map(([type, values]) =>
              values?.length ? (
                <div key={type} className="mb-3">
                  <div className="text-gray-500 text-xs uppercase mb-1">{type}</div>
                  {values.map((v) => (
                    <div key={v} className="font-mono text-sm text-green-400 bg-gray-800 px-2 py-1 rounded mb-1">{v}</div>
                  ))}
                </div>
              ) : null
            )}
          </div>
        )}

        {inc.source_url && (
          <div className="bg-gray-900 rounded-lg p-4 mb-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">Source</div>
            <a href={inc.source_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline text-sm break-all">
              {inc.source_url}
            </a>
          </div>
        )}

        {/* Enrichment */}
        <EnrichButton
          incidentId={inc.id}
          iocs={inc.iocs as Record<string, string[]> | null}
        />

        {/* Saved enrichment results (from previous runs) */}
        {inc.enrichment && (
          <div className="bg-gray-900 rounded-lg p-4 mt-4">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">Last Saved Enrichment</div>
            <pre className="text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap">{JSON.stringify(inc.enrichment, null, 2)}</pre>
          </div>
        )}
      </div>
    </main>
  )
}
