import { getSupabaseServer } from '@/lib/supabase'
import Link from 'next/link'
import SeverityChart from '@/components/SeverityChart'
import SectorChart from '@/components/SectorChart'
import ExposureChart from '@/components/ExposureChart'
import SignOutButton from '@/components/SignOutButton'

export const dynamic = 'force-dynamic'

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

export default async function Home() {
  const supabase = getSupabaseServer()

  const [{ data: incidents }, { data: assets }, { data: threatGroups }] = await Promise.all([
    supabase.from('incidents').select('*').order('created_at', { ascending: false }),
    supabase.from('maritime_assets').select('*').order('exposure_score', { ascending: false }),
    supabase.from('threat_groups').select('*').order('victim_count', { ascending: false }),
  ])

  return (
    <main className="min-h-screen bg-gray-950 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Maritime Cyber Dashboard</h1>
            <p className="text-gray-400 mt-1">MTS-OPS-CENTER — Threat intelligence platform</p>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/account" className="text-sm text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 px-3 py-1.5 rounded transition-colors">
              Account
            </Link>
            <SignOutButton />
          </div>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        {[
          { label: 'Incidents', value: incidents?.length ?? 0, color: 'border-red-600' },
          { label: 'Maritime Assets', value: assets?.length ?? 0, color: 'border-blue-500' },
          { label: 'Threat Groups', value: threatGroups?.length ?? 0, color: 'border-orange-500' },
        ].map(({ label, value, color }) => (
          <div key={label} className={`bg-gray-900 rounded-lg p-4 border-l-4 ${color}`}>
            <div className="text-3xl font-bold">{value}</div>
            <div className="text-gray-400 text-sm mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <SeverityChart incidents={incidents ?? []} />
        <SectorChart incidents={incidents ?? []} />
        <ExposureChart assets={assets ?? []} />
      </div>

      <div className="grid grid-cols-1 gap-8">
        {/* Incidents */}
        <section>
          <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
            Incidents
          </h2>
          <div className="bg-gray-900 rounded-lg overflow-hidden">
            {!incidents?.length ? (
              <p className="text-gray-500 p-6">No incidents recorded.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-800">
                    <th className="text-left p-3 font-medium">Title</th>
                    <th className="text-left p-3 font-medium">Severity</th>
                    <th className="text-left p-3 font-medium">Sector</th>
                    <th className="text-left p-3 font-medium">Attack Vector</th>
                    <th className="text-left p-3 font-medium">Threat Group</th>
                    <th className="text-left p-3 font-medium">Target</th>
                    <th className="text-left p-3 font-medium">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc, i) => (
                    <tr key={inc.id} className={`${i % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800/50'} hover:bg-gray-700 cursor-pointer`}>
                      <td className="p-3 font-medium max-w-xs truncate">
                        <Link href={`/incidents/${inc.id}`} className="hover:text-blue-400">{inc.title}</Link>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_COLOR[inc.severity] ?? 'bg-gray-600 text-white'}`}>
                          {inc.severity}
                        </span>
                      </td>
                      <td className="p-3 text-gray-300">{inc.sector}</td>
                      <td className="p-3 text-gray-300">{inc.attack_vector}</td>
                      <td className="p-3 text-gray-400">{inc.threat_group ?? '—'}</td>
                      <td className="p-3 text-gray-400">{inc.target_organization ?? inc.target_country ?? '—'}</td>
                      <td className="p-3 text-gray-500 whitespace-nowrap">
                        {new Date(inc.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Maritime Assets */}
        <section>
          <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" />
            Maritime Assets
          </h2>
          <div className="bg-gray-900 rounded-lg overflow-hidden">
            {!assets?.length ? (
              <p className="text-gray-500 p-6">No assets recorded.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-800">
                    <th className="text-left p-3 font-medium">Name</th>
                    <th className="text-left p-3 font-medium">Type</th>
                    <th className="text-left p-3 font-medium">Country</th>
                    <th className="text-left p-3 font-medium">Exposure Score</th>
                    <th className="text-left p-3 font-medium">Vulnerabilities</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset, i) => (
                    <tr key={asset.id} className={`${i % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800/50'} hover:bg-gray-700 cursor-pointer`}>
                      <td className="p-3 font-medium">
                        <Link href={`/maritime-assets/${asset.id}`} className="hover:text-blue-400">{asset.name}</Link>
                      </td>
                      <td className="p-3 text-gray-300">{asset.asset_type}</td>
                      <td className="p-3 text-gray-400">{asset.country ?? '—'}</td>
                      <td className="p-3">
                        <span className={`font-bold ${EXPOSURE_COLOR(asset.exposure_score)}`}>
                          {asset.exposure_score}
                        </span>
                        <span className="text-gray-600 text-xs"> / 100</span>
                      </td>
                      <td className="p-3 text-gray-400">
                        {asset.vulnerabilities?.length ?? 0} CVE{asset.vulnerabilities?.length !== 1 ? 's' : ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Threat Groups */}
        <section>
          <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-orange-500 inline-block" />
            Threat Groups
          </h2>
          <div className="bg-gray-900 rounded-lg overflow-hidden">
            {!threatGroups?.length ? (
              <p className="text-gray-500 p-6">No threat groups recorded.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-800">
                    <th className="text-left p-3 font-medium">Name</th>
                    <th className="text-left p-3 font-medium">Status</th>
                    <th className="text-left p-3 font-medium">Victims</th>
                    <th className="text-left p-3 font-medium">TTPs</th>
                    <th className="text-left p-3 font-medium">Last Activity</th>
                    <th className="text-left p-3 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {threatGroups.map((group, i) => (
                    <tr key={group.id} className={`${i % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800/50'} hover:bg-gray-700 cursor-pointer`}>
                      <td className="p-3 font-semibold">
                        <Link href={`/threat-groups/${group.id}`} className="hover:text-blue-400">{group.name}</Link>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${group.active ? 'bg-red-600 text-white' : 'bg-gray-600 text-gray-300'}`}>
                          {group.active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="p-3 text-gray-300">{group.victim_count}</td>
                      <td className="p-3 text-gray-400">{group.ttps?.length ?? 0} TTPs</td>
                      <td className="p-3 text-gray-500 whitespace-nowrap">
                        {new Date(group.last_activity).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-gray-400 max-w-xs truncate">{group.description ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </div>
    </main>
  )
}
