'use client'

import { useState } from 'react'

interface EnrichResult {
  target: string
  type: string
  virustotal?: {
    malicious: number
    suspicious: number
    harmless: number
    undetected: number
    reputation: number | null
    country: string | null
    asn: number | null
    tags: string[]
  }
  shodan?: {
    org: string | null
    isp: string | null
    country: string | null
    os: string | null
    open_ports: number[]
    vulns: string[]
    tags: string[]
    last_update: string | null
  }
  abuseipdb?: {
    abuse_confidence_score: number
    total_reports: number
    country: string | null
    isp: string | null
    domain: string | null
    usage_type: string | null
    is_tor: boolean
    last_reported: string | null
  }
}

interface Props {
  incidentId: string
  iocs: Record<string, string[]> | null
}

function ScoreBar({ value, max = 100, color }: { value: number; max?: number; color: string }) {
  const pct = Math.min(100, Math.round((value / max) * 100))
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-700 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs w-8 text-right">{value}</span>
    </div>
  )
}

export default function EnrichButton({ incidentId, iocs }: Props) {
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<EnrichResult[]>([])
  const [error, setError] = useState<string | null>(null)
  const [target, setTarget] = useState('')

  // Flatten IOC values for quick-pick
  const allIocs: string[] = []
  if (iocs) {
    for (const vals of Object.values(iocs)) {
      if (Array.isArray(vals)) allIocs.push(...vals)
    }
  }

  async function enrich(t: string) {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: t, incident_id: incidentId }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json.error ?? 'Enrichment failed')
      setResults(prev => {
        const existing = prev.findIndex(r => r.target === json.target)
        if (existing >= 0) {
          const copy = [...prev]
          copy[existing] = json
          return copy
        }
        return [...prev, json]
      })
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs uppercase tracking-wide mb-3">Threat Intelligence Enrichment</div>

      {/* Manual target input */}
      <div className="flex gap-2 mb-3">
        <input
          type="text"
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="IP, domain, hash, or URL…"
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          onKeyDown={e => e.key === 'Enter' && target.trim() && enrich(target.trim())}
        />
        <button
          onClick={() => target.trim() && enrich(target.trim())}
          disabled={loading || !target.trim()}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded transition-colors"
        >
          {loading ? 'Querying…' : 'Enrich'}
        </button>
      </div>

      {/* Quick-pick from existing IOCs */}
      {allIocs.length > 0 && (
        <div className="mb-3">
          <div className="text-gray-500 text-xs mb-1.5">Quick-enrich from IOCs:</div>
          <div className="flex flex-wrap gap-1.5">
            {allIocs.map(ioc => (
              <button
                key={ioc}
                onClick={() => enrich(ioc)}
                disabled={loading}
                className="font-mono text-xs bg-gray-800 hover:bg-gray-700 text-green-400 px-2 py-0.5 rounded border border-gray-700 hover:border-gray-500 transition-colors disabled:opacity-50"
              >
                {ioc}
              </button>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div className="text-red-400 text-sm bg-red-950/40 border border-red-800 rounded px-3 py-2 mb-3">{error}</div>
      )}

      {/* Results */}
      {results.map(result => (
        <div key={result.target} className="mt-4 border border-gray-800 rounded-lg overflow-hidden">
          <div className="bg-gray-800 px-4 py-2 flex items-center justify-between">
            <span className="font-mono text-sm text-white">{result.target}</span>
            <span className="text-xs text-gray-400 bg-gray-700 px-2 py-0.5 rounded uppercase">{result.type}</span>
          </div>

          <div className="divide-y divide-gray-800">
            {/* VirusTotal */}
            {result.virustotal && (
              <div className="p-4">
                <div className="text-xs font-semibold text-gray-300 mb-2 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" />
                  VirusTotal
                  {result.virustotal.country && <span className="text-gray-500 font-normal ml-auto">{result.virustotal.country}</span>}
                  {result.virustotal.asn && <span className="text-gray-600 font-normal">AS{result.virustotal.asn}</span>}
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                  <div>
                    <div className="text-xs text-red-400 mb-0.5">Malicious ({result.virustotal.malicious})</div>
                    <ScoreBar value={result.virustotal.malicious} max={Math.max(result.virustotal.malicious + result.virustotal.suspicious + result.virustotal.harmless + result.virustotal.undetected, 1)} color="bg-red-500" />
                  </div>
                  <div>
                    <div className="text-xs text-yellow-400 mb-0.5">Suspicious ({result.virustotal.suspicious})</div>
                    <ScoreBar value={result.virustotal.suspicious} max={Math.max(result.virustotal.malicious + result.virustotal.suspicious + result.virustotal.harmless + result.virustotal.undetected, 1)} color="bg-yellow-500" />
                  </div>
                </div>
                {result.virustotal.reputation !== null && (
                  <div className="text-xs text-gray-400 mt-2">Reputation score: <span className={result.virustotal.reputation < 0 ? 'text-red-400' : 'text-green-400'}>{result.virustotal.reputation}</span></div>
                )}
                {result.virustotal.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {result.virustotal.tags.map(tag => (
                      <span key={tag} className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{tag}</span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Shodan */}
            {result.shodan && (
              <div className="p-4">
                <div className="text-xs font-semibold text-gray-300 mb-2 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-orange-500 inline-block" />
                  Shodan
                  {result.shodan.country && <span className="text-gray-500 font-normal ml-auto">{result.shodan.country}</span>}
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {result.shodan.org && <div><span className="text-gray-500">Org: </span><span className="text-gray-200">{result.shodan.org}</span></div>}
                  {result.shodan.isp && <div><span className="text-gray-500">ISP: </span><span className="text-gray-200">{result.shodan.isp}</span></div>}
                  {result.shodan.os && <div><span className="text-gray-500">OS: </span><span className="text-gray-200">{result.shodan.os}</span></div>}
                </div>
                {result.shodan.open_ports.length > 0 && (
                  <div className="mt-2">
                    <div className="text-xs text-gray-500 mb-1">Open ports:</div>
                    <div className="flex flex-wrap gap-1">
                      {result.shodan.open_ports.map(p => (
                        <span key={p} className="text-xs font-mono bg-gray-800 text-blue-300 px-1.5 py-0.5 rounded border border-gray-700">{p}</span>
                      ))}
                    </div>
                  </div>
                )}
                {result.shodan.vulns.length > 0 && (
                  <div className="mt-2">
                    <div className="text-xs text-red-400 mb-1">CVEs ({result.shodan.vulns.length}):</div>
                    <div className="flex flex-wrap gap-1">
                      {result.shodan.vulns.map(cve => (
                        <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                          className="text-xs font-mono bg-red-950/40 text-red-300 px-1.5 py-0.5 rounded border border-red-900 hover:border-red-600 transition-colors">
                          {cve}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* AbuseIPDB */}
            {result.abuseipdb && (
              <div className="p-4">
                <div className="text-xs font-semibold text-gray-300 mb-2 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
                  AbuseIPDB
                  {result.abuseipdb.country && <span className="text-gray-500 font-normal ml-auto">{result.abuseipdb.country}</span>}
                  {result.abuseipdb.is_tor && <span className="text-xs bg-purple-900 text-purple-300 px-1.5 py-0.5 rounded">TOR</span>}
                </div>
                <div className="mb-2">
                  <div className="text-xs text-gray-400 mb-0.5">Abuse confidence: <span className={result.abuseipdb.abuse_confidence_score >= 75 ? 'text-red-400' : result.abuseipdb.abuse_confidence_score >= 25 ? 'text-yellow-400' : 'text-green-400'}>{result.abuseipdb.abuse_confidence_score}%</span></div>
                  <ScoreBar value={result.abuseipdb.abuse_confidence_score} color={result.abuseipdb.abuse_confidence_score >= 75 ? 'bg-red-500' : result.abuseipdb.abuse_confidence_score >= 25 ? 'bg-yellow-500' : 'bg-green-500'} />
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div><span className="text-gray-500">Reports: </span><span className="text-gray-200">{result.abuseipdb.total_reports}</span></div>
                  {result.abuseipdb.isp && <div><span className="text-gray-500">ISP: </span><span className="text-gray-200">{result.abuseipdb.isp}</span></div>}
                  {result.abuseipdb.usage_type && <div><span className="text-gray-500">Type: </span><span className="text-gray-200">{result.abuseipdb.usage_type}</span></div>}
                  {result.abuseipdb.last_reported && <div><span className="text-gray-500">Last report: </span><span className="text-gray-200">{new Date(result.abuseipdb.last_reported).toLocaleDateString()}</span></div>}
                </div>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
