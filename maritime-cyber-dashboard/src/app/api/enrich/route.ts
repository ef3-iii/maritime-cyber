import { NextRequest, NextResponse } from 'next/server'
import { getSupabaseServer } from '@/lib/supabase'

type EnrichTarget = 'ip' | 'domain' | 'hash' | 'url'

function detectTargetType(target: string): EnrichTarget {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) return 'ip'
  if (/^[a-f0-9]{32,64}$/i.test(target)) return 'hash'
  if (/^https?:\/\//.test(target)) return 'url'
  return 'domain'
}

async function queryVirusTotal(target: string, type: EnrichTarget) {
  const key = process.env.VIRUSTOTAL_API_KEY!
  const endpoint = type === 'ip'
    ? `https://www.virustotal.com/api/v3/ip_addresses/${target}`
    : type === 'hash'
      ? `https://www.virustotal.com/api/v3/files/${target}`
      : type === 'url'
        ? `https://www.virustotal.com/api/v3/urls/${Buffer.from(target).toString('base64').replace(/=/g, '')}`
        : `https://www.virustotal.com/api/v3/domains/${target}`

  const res = await fetch(endpoint, { headers: { 'x-apikey': key } })
  if (!res.ok) return null
  const json = await res.json()
  const stats = json.data?.attributes?.last_analysis_stats
  return {
    source: 'VirusTotal',
    malicious: stats?.malicious ?? 0,
    suspicious: stats?.suspicious ?? 0,
    harmless: stats?.harmless ?? 0,
    undetected: stats?.undetected ?? 0,
    reputation: json.data?.attributes?.reputation ?? null,
    country: json.data?.attributes?.country ?? null,
    asn: json.data?.attributes?.asn ?? null,
    tags: json.data?.attributes?.tags ?? [],
  }
}

async function queryShodan(ip: string) {
  const key = process.env.SHODAN_API_KEY!
  const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${key}`)
  if (!res.ok) return null
  const json = await res.json()
  return {
    source: 'Shodan',
    org: json.org ?? null,
    isp: json.isp ?? null,
    country: json.country_name ?? null,
    os: json.os ?? null,
    open_ports: json.ports ?? [],
    vulns: json.vulns ? Object.keys(json.vulns) : [],
    tags: json.tags ?? [],
    last_update: json.last_update ?? null,
  }
}

async function queryAbuseIPDB(ip: string) {
  const key = process.env.ABUSEIPDB_API_KEY!
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
    { headers: { Key: key, Accept: 'application/json' } }
  )
  if (!res.ok) return null
  const json = await res.json()
  const d = json.data
  return {
    source: 'AbuseIPDB',
    abuse_confidence_score: d?.abuseConfidenceScore ?? 0,
    total_reports: d?.totalReports ?? 0,
    country: d?.countryCode ?? null,
    isp: d?.isp ?? null,
    domain: d?.domain ?? null,
    usage_type: d?.usageType ?? null,
    is_tor: d?.isTor ?? false,
    last_reported: d?.lastReportedAt ?? null,
  }
}

export async function POST(req: NextRequest) {
  // Auth check
  const supabase = getSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const body = await req.json()
  const { target, incident_id } = body

  if (!target || typeof target !== 'string') {
    return NextResponse.json({ error: 'target is required' }, { status: 400 })
  }

  const type = detectTargetType(target)
  const results: Record<string, unknown> = { target, type }

  // Always query VirusTotal
  const vt = await queryVirusTotal(target, type)
  if (vt) results.virustotal = vt

  // Shodan + AbuseIPDB for IPs only
  if (type === 'ip') {
    const [shodan, abuse] = await Promise.all([
      queryShodan(target),
      queryAbuseIPDB(target),
    ])
    if (shodan) results.shodan = shodan
    if (abuse) results.abuseipdb = abuse
  }

  // Optionally attach enrichment to an incident's IOCs
  if (incident_id) {
    await supabase
      .from('incidents')
      .update({ enrichment: results })
      .eq('id', incident_id)
  }

  return NextResponse.json(results)
}
