import { NextRequest, NextResponse } from 'next/server'
import { createClient } from '@supabase/supabase-js'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type Sector = 'Maritime' | 'Energy' | 'Transportation' | 'Water' | 'Healthcare' | 'Financial' | 'Telecom' | 'Government' | 'Manufacturing'
type AttackVector = 'Ransomware' | 'Phishing' | 'Supply Chain' | 'Vulnerability Exploitation' | 'DDoS' | 'Insider Threat' | 'Malware' | 'Network Intrusion' | 'IoT/OT Compromise'
type ThreatGroup = 'LockBit3' | 'Akira' | 'BlackCat' | 'Cl0p' | 'Play' | 'Unknown'

interface IncidentPayload {
  title: string
  description?: string
  threat_group?: ThreatGroup
  severity: Severity
  sector: Sector
  attack_vector: AttackVector
  target_organization?: string
  target_country?: string
  iocs?: {
    ips?: string[]
    domains?: string[]
    hashes?: string[]
    urls?: string[]
  }
  source_url?: string
}

interface MaritimeAssetPayload {
  name: string
  asset_type: 'Port' | 'Vessel' | 'Terminal' | 'Offshore Platform' | 'Shipping Company'
  country?: string
  exposure_score?: number
  vulnerabilities?: {
    cve_id: string
    severity: string
    description: string
  }[]
}

interface ThreatGroupPayload {
  name: ThreatGroup
  description?: string
  ttps?: string[]
  victim_count?: number
  last_activity?: string
  active?: boolean
}

type IngestPayload =
  | { type: 'incident'; data: IncidentPayload }
  | { type: 'maritime_asset'; data: MaritimeAssetPayload }
  | { type: 'threat_group'; data: ThreatGroupPayload }

const VALID_TYPES = ['incident', 'maritime_asset', 'threat_group']
const VALID_SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low']
const VALID_SECTORS: Sector[] = ['Maritime', 'Energy', 'Transportation', 'Water', 'Healthcare', 'Financial', 'Telecom', 'Government', 'Manufacturing']
const VALID_VECTORS: AttackVector[] = ['Ransomware', 'Phishing', 'Supply Chain', 'Vulnerability Exploitation', 'DDoS', 'Insider Threat', 'Malware', 'Network Intrusion', 'IoT/OT Compromise']
const VALID_ASSET_TYPES = ['Port', 'Vessel', 'Terminal', 'Offshore Platform', 'Shipping Company']

function authenticate(req: NextRequest): boolean {
  const expectedKey = process.env.INGEST_API_KEY
  if (!expectedKey) return true

  const apiKey = req.headers.get('x-api-key')
  if (apiKey === expectedKey) return true

  const auth = req.headers.get('authorization')
  if (auth?.startsWith('Bearer ') && auth.slice(7) === expectedKey) return true

  return false
}

function validatePayload(body: unknown): { valid: boolean; error?: string } {
  if (!body || typeof body !== 'object') return { valid: false, error: 'Invalid JSON body' }

  const b = body as Record<string, unknown>

  if (!('type' in b)) return { valid: false, error: 'Missing required field: type' }
  if (!('data' in b)) return { valid: false, error: 'Missing required field: data' }
  if (!VALID_TYPES.includes(b.type as string)) return { valid: false, error: `Invalid type. Must be one of: ${VALID_TYPES.join(', ')}` }
  if (!b.data || typeof b.data !== 'object') return { valid: false, error: 'data must be a non-null object' }

  const data = b.data as Record<string, unknown>

  if (b.type === 'incident') {
    if (!data.title || typeof data.title !== 'string' || data.title.length === 0)
      return { valid: false, error: 'incident.title is required and must be non-empty' }
    if (!VALID_SEVERITIES.includes(data.severity as Severity))
      return { valid: false, error: `incident.severity must be one of: ${VALID_SEVERITIES.join(', ')}` }
    if (!VALID_SECTORS.includes(data.sector as Sector))
      return { valid: false, error: `incident.sector must be one of: ${VALID_SECTORS.join(', ')}` }
    if (!VALID_VECTORS.includes(data.attack_vector as AttackVector))
      return { valid: false, error: `incident.attack_vector must be one of: ${VALID_VECTORS.join(', ')}` }
  }

  if (b.type === 'maritime_asset') {
    if (!data.name || typeof data.name !== 'string' || data.name.length === 0)
      return { valid: false, error: 'maritime_asset.name is required and must be non-empty' }
    if (!VALID_ASSET_TYPES.includes(data.asset_type as string))
      return { valid: false, error: `maritime_asset.asset_type must be one of: ${VALID_ASSET_TYPES.join(', ')}` }
  }

  if (b.type === 'threat_group') {
    if (!data.name || typeof data.name !== 'string' || data.name.length === 0)
      return { valid: false, error: 'threat_group.name is required and must be non-empty' }
  }

  return { valid: true }
}

function getSupabase() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  if (!url || !key) throw new Error('Supabase environment variables not configured')
  return createClient(url, key)
}

export async function GET() {
  return NextResponse.json({
    status: 'ok',
    endpoint: '/api/ingest',
    methods: ['POST'],
    examples: {
      incident: {
        type: 'incident',
        data: {
          title: 'Ransomware Attack on Port Terminal',
          severity: 'Critical',
          sector: 'Maritime',
          attack_vector: 'Ransomware',
        },
      },
      maritime_asset: {
        type: 'maritime_asset',
        data: {
          name: 'Port of Los Angeles',
          asset_type: 'Port',
          country: 'USA',
        },
      },
      threat_group: {
        type: 'threat_group',
        data: {
          name: 'LockBit3',
          victim_count: 95,
          active: true,
        },
      },
    },
  })
}

export async function POST(req: NextRequest) {
  if (!authenticate(req)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
  }

  const { valid, error } = validatePayload(body)
  if (!valid) {
    return NextResponse.json({ error }, { status: 400 })
  }

  const payload = body as IngestPayload

  let supabase: ReturnType<typeof getSupabase>
  try {
    supabase = getSupabase()
  } catch (err: unknown) {
    return NextResponse.json({ error: (err as Error).message }, { status: 503 })
  }

  if (payload.type === 'incident') {
    const { error: dbError } = await supabase.from('incidents').insert({
      ...payload.data,
      created_at: new Date().toISOString(),
    })
    if (dbError) return NextResponse.json({ error: dbError.message }, { status: 500 })
  }

  if (payload.type === 'maritime_asset') {
    const data = payload.data as MaritimeAssetPayload
    const { error: dbError } = await supabase.from('maritime_assets').insert({
      ...data,
      exposure_score: data.exposure_score ?? 0,
      created_at: new Date().toISOString(),
    })
    if (dbError) return NextResponse.json({ error: dbError.message }, { status: 500 })
  }

  if (payload.type === 'threat_group') {
    const data = payload.data as ThreatGroupPayload
    const { error: dbError } = await supabase.from('threat_groups').insert({
      ...data,
      active: data.active ?? true,
      victim_count: data.victim_count ?? 0,
      last_activity: data.last_activity ?? new Date().toISOString(),
      created_at: new Date().toISOString(),
    })
    if (dbError) return NextResponse.json({ error: dbError.message }, { status: 500 })
  }

  return NextResponse.json({ success: true }, { status: 201 })
}
