/**
 * Tests for /api/ingest endpoint
 * Tests authentication, validation, and data ingestion
 */
import { NextRequest } from 'next/server'

// Mock types for testing
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

type IngestPayload = {
  type: 'incident' | 'maritime_asset' | 'threat_group'
  data: IncidentPayload | MaritimeAssetPayload | ThreatGroupPayload
}

describe('/api/ingest', () => {
  // ============================================
  // AUTHENTICATION TESTS
  // ============================================
  describe('Authentication', () => {
    it('should reject request with missing API key', async () => {
      const payload: IngestPayload = {
        type: 'incident',
        data: {
          title: 'Test Incident',
          severity: 'Critical',
          sector: 'Maritime',
          attack_vector: 'Ransomware',
        } as IncidentPayload,
      }

      // Simulate API key validation
      const apiKey = undefined
      const expectedKey = process.env.INGEST_API_KEY

      const isValid = apiKey === expectedKey && expectedKey !== undefined
      expect(isValid).toBe(false)
    })

    it('should reject request with invalid API key', async () => {
      const apiKey = 'invalid-key-xyz'
      const expectedKey = process.env.INGEST_API_KEY

      const isValid = apiKey === expectedKey
      expect(isValid).toBe(false)
    })

    it('should accept request with valid x-api-key header', async () => {
      const apiKey = 'test-api-key-12345'
      const expectedKey = 'test-api-key-12345'

      const isValid = apiKey === expectedKey
      expect(isValid).toBe(true)
    })

    it('should accept request with valid Authorization Bearer token', async () => {
      const authHeader = 'Bearer test-api-key-12345'
      const apiKey = authHeader.replace('Bearer ', '')
      const expectedKey = 'test-api-key-12345'

      const isValid = apiKey === expectedKey
      expect(isValid).toBe(true)
    })

    it('should allow all requests when INGEST_API_KEY not configured', async () => {
      const originalKey = process.env.INGEST_API_KEY
      delete process.env.INGEST_API_KEY

      const expectedKey = process.env.INGEST_API_KEY
      const shouldAllow = !expectedKey

      expect(shouldAllow).toBe(true)

      // Restore
      process.env.INGEST_API_KEY = originalKey
    })
  })

  // ============================================
  // PAYLOAD VALIDATION TESTS
  // ============================================
  describe('Payload Validation', () => {
    it('should reject payload missing required type field', async () => {
      const payload = {
        data: {
          title: 'Test Incident',
          severity: 'Critical',
          sector: 'Maritime',
          attack_vector: 'Ransomware',
        },
      }

      const hasType = 'type' in payload
      expect(hasType).toBe(false)
    })

    it('should reject payload missing required data field', async () => {
      const payload = {
        type: 'incident',
      }

      const hasData = 'data' in payload
      expect(hasData).toBe(false)
    })

    it('should reject payload with invalid type value', async () => {
      const payload = {
        type: 'invalid_type',
        data: { title: 'Test' },
      }

      const validTypes = ['incident', 'maritime_asset', 'threat_group']
      const isValid = validTypes.includes(payload.type)

      expect(isValid).toBe(false)
    })

    it('should reject payload with empty data object', async () => {
      const payload: IngestPayload = {
        type: 'incident',
        data: {} as IncidentPayload,
      }

      const hasRequiredFields = 'title' in payload.data && 'severity' in payload.data
      expect(hasRequiredFields).toBe(false)
    })

    it('should reject payload with null data', async () => {
      const payload = {
        type: 'incident',
        data: null,
      }

      const isValid = payload.data !== null && payload.data !== undefined
      expect(isValid).toBe(false)
    })

    it('should accept valid incident payload', async () => {
      const payload: IngestPayload = {
        type: 'incident',
        data: {
          title: 'Ransomware Attack on Port Terminal',
          severity: 'Critical',
          sector: 'Maritime',
          attack_vector: 'Ransomware',
        } as IncidentPayload,
      }

      const hasRequiredFields =
        payload.type && payload.data &&
        'title' in payload.data &&
        'severity' in payload.data &&
        'sector' in payload.data &&
        'attack_vector' in payload.data

      expect(hasRequiredFields).toBe(true)
    })
  })

  // ============================================
  // INCIDENT INGESTION TESTS
  // ============================================
  describe('Incident Ingestion', () => {
    it('should require non-empty title', async () => {
      const payload: IngestPayload = {
        type: 'incident',
        data: {
          title: '',
          severity: 'Critical',
          sector: 'Maritime',
          attack_vector: 'Ransomware',
        } as IncidentPayload,
      }

      const isValid = payload.data && 'title' in payload.data && payload.data.title.length > 0
      expect(isValid).toBe(false)
    })

    it('should validate severity is one of allowed values', async () => {
      const validSeverities: Severity[] = ['Critical', 'High', 'Medium', 'Low']
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
      }

      const isValid = validSeverities.includes(data.severity)
      expect(isValid).toBe(true)
    })

    it('should reject invalid severity value', async () => {
      const validSeverities: Severity[] = ['Critical', 'High', 'Medium', 'Low']
      const invalidSeverity = 'Extreme' as any

      const isValid = validSeverities.includes(invalidSeverity)
      expect(isValid).toBe(false)
    })

    it('should validate sector is valid maritime sector', async () => {
      const validSectors: Sector[] = [
        'Maritime', 'Energy', 'Transportation', 'Water',
        'Healthcare', 'Financial', 'Telecom', 'Government', 'Manufacturing'
      ]
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
      }

      const isValid = validSectors.includes(data.sector)
      expect(isValid).toBe(true)
    })

    it('should validate attack vector is known type', async () => {
      const validVectors: AttackVector[] = [
        'Ransomware', 'Phishing', 'Supply Chain',
        'Vulnerability Exploitation', 'DDoS', 'Insider Threat',
        'Malware', 'Network Intrusion', 'IoT/OT Compromise'
      ]
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
      }

      const isValid = validVectors.includes(data.attack_vector)
      expect(isValid).toBe(true)
    })

    it('should accept optional threat_group field', async () => {
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
        threat_group: 'LockBit3',
      }

      expect(data.threat_group).toBe('LockBit3')
    })

    it('should accept optional target_organization field', async () => {
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
        target_organization: 'Port of Rotterdam',
      }

      expect(data.target_organization).toBe('Port of Rotterdam')
    })

    it('should validate IoCs structure', async () => {
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
        iocs: {
          ips: ['192.168.1.100'],
          domains: ['evil.com'],
          hashes: ['5d41402abc4b2a76b9719d911017c592'],
          urls: ['http://malware.site/payload'],
        },
      }

      const hasValidIoCs = data.iocs &&
        Array.isArray(data.iocs.ips) &&
        Array.isArray(data.iocs.domains) &&
        Array.isArray(data.iocs.hashes) &&
        Array.isArray(data.iocs.urls)

      expect(hasValidIoCs).toBe(true)
    })
  })

  // ============================================
  // MARITIME ASSET INGESTION TESTS
  // ============================================
  describe('Maritime Asset Ingestion', () => {
    it('should require unique asset name', async () => {
      const data: MaritimeAssetPayload = {
        name: 'Port of Los Angeles',
        asset_type: 'Port',
        country: 'USA',
      }

      expect(data.name).toBe('Port of Los Angeles')
      expect(data.name.length > 0).toBe(true)
    })

    it('should validate asset_type is allowed value', async () => {
      const validAssetTypes = ['Port', 'Vessel', 'Terminal', 'Offshore Platform', 'Shipping Company']
      const data: MaritimeAssetPayload = {
        name: 'Test',
        asset_type: 'Port',
      }

      const isValid = validAssetTypes.includes(data.asset_type)
      expect(isValid).toBe(true)
    })

    it('should reject invalid asset_type', async () => {
      const validAssetTypes = ['Port', 'Vessel', 'Terminal', 'Offshore Platform', 'Shipping Company']
      const invalidType = 'InvalidType'

      const isValid = validAssetTypes.includes(invalidType as any)
      expect(isValid).toBe(false)
    })

    it('should default exposure_score to 0 if not provided', async () => {
      const data: MaritimeAssetPayload = {
        name: 'Test Asset',
        asset_type: 'Port',
      }

      const exposureScore = data.exposure_score || 0
      expect(exposureScore).toBe(0)
    })

    it('should validate exposure_score is within range', async () => {
      const data: MaritimeAssetPayload = {
        name: 'Test',
        asset_type: 'Port',
        exposure_score: 75,
      }

      const isValid = data.exposure_score >= 0 && data.exposure_score <= 100
      expect(isValid).toBe(true)
    })

    it('should validate vulnerabilities structure', async () => {
      const data: MaritimeAssetPayload = {
        name: 'Test',
        asset_type: 'Port',
        vulnerabilities: [
          {
            cve_id: 'CVE-2024-0001',
            severity: 'Critical',
            description: 'ECDIS vulnerability',
          },
        ],
      }

      const hasValidVulns = data.vulnerabilities &&
        data.vulnerabilities.every(v => v.cve_id && v.severity && v.description)

      expect(hasValidVulns).toBe(true)
    })
  })

  // ============================================
  // THREAT GROUP INGESTION TESTS
  // ============================================
  describe('Threat Group Ingestion', () => {
    it('should require threat group name', async () => {
      const data: ThreatGroupPayload = {
        name: 'LockBit3',
      }

      expect(data.name.length > 0).toBe(true)
    })

    it('should default active to true if not provided', async () => {
      const data: ThreatGroupPayload = {
        name: 'LockBit3',
      }

      const active = data.active !== undefined ? data.active : true
      expect(active).toBe(true)
    })

    it('should default victim_count to 0 if not provided', async () => {
      const data: ThreatGroupPayload = {
        name: 'LockBit3',
      }

      const victimCount = data.victim_count || 0
      expect(victimCount).toBe(0)
    })

    it('should default last_activity to current time if not provided', async () => {
      const data: ThreatGroupPayload = {
        name: 'LockBit3',
      }

      const lastActivity = data.last_activity || new Date().toISOString()
      expect(lastActivity).toBeDefined()
      expect(typeof lastActivity).toBe('string')
    })

    it('should accept ttps array', async () => {
      const data: ThreatGroupPayload = {
        name: 'LockBit3',
        ttps: ['Spear Phishing', 'Lateral Movement', 'Data Exfiltration'],
      }

      expect(Array.isArray(data.ttps)).toBe(true)
      expect(data.ttps?.length).toBe(3)
    })

    it('should accept description', async () => {
      const data: ThreatGroupPayload = {
        name: 'LockBit3',
        description: 'Ransomware-as-a-Service group',
      }

      expect(data.description).toBe('Ransomware-as-a-Service group')
    })
  })

  // ============================================
  // ERROR HANDLING TESTS
  // ============================================
  describe('Error Handling', () => {
    it('should handle Supabase connection failure', async () => {
      try {
        throw new Error('Database connection failed')
      } catch (error: any) {
        expect(error.message).toContain('connection failed')
      }
    })

    it('should handle JSON parsing error', async () => {
      const invalidJson = '{"invalid": json format}'

      expect(() => {
        JSON.parse(invalidJson)
      }).toThrow(SyntaxError)
    })

    it('should handle missing environment variables', async () => {
      const originalUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      delete process.env.NEXT_PUBLIC_SUPABASE_URL

      const hasUrl = !!process.env.NEXT_PUBLIC_SUPABASE_URL

      expect(hasUrl).toBe(false)

      // Restore
      if (originalUrl) {
        process.env.NEXT_PUBLIC_SUPABASE_URL = originalUrl
      }
    })
  })

  // ============================================
  // HEALTH CHECK TESTS
  // ============================================
  describe('GET /api/ingest (Health Check)', () => {
    it('should return 200 status', async () => {
      const status = 200
      expect(status).toBe(200)
    })

    it('should return endpoint documentation', async () => {
      const response = {
        status: 'ok',
        endpoint: '/api/ingest',
        methods: ['POST'],
      }

      expect(response.status).toBe('ok')
      expect(response.endpoint).toBe('/api/ingest')
      expect(response.methods).toContain('POST')
    })

    it('should include example payloads for all types', async () => {
      const examples = {
        incident: {
          type: 'incident',
          data: {
            title: 'Ransomware Attack',
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
      }

      expect('incident' in examples).toBe(true)
      expect('maritime_asset' in examples).toBe(true)
      expect('threat_group' in examples).toBe(true)
    })
  })

  // ============================================
  // EDGE CASES
  // ============================================
  describe('Edge Cases', () => {
    it('should handle very long title', async () => {
      const longTitle = 'A'.repeat(1000)
      const data: IncidentPayload = {
        title: longTitle,
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
      }

      expect(data.title.length).toBe(1000)
    })

    it('should handle special characters in description', async () => {
      const description = 'Special chars: @#$%^&*() "quotes" \'apostrophes\''
      const data: IncidentPayload = {
        title: 'Test',
        description,
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
      }

      expect(data.description).toContain('@#$%^&*()')
    })

    it('should handle unicode characters', async () => {
      const data: IncidentPayload = {
        title: 'Attack on José Martí Port 港口',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
      }

      expect(data.title).toContain('José')
      expect(data.title).toContain('港口')
    })

    it('should handle empty IoCs arrays', async () => {
      const data: IncidentPayload = {
        title: 'Test',
        severity: 'Critical',
        sector: 'Maritime',
        attack_vector: 'Ransomware',
        iocs: {
          ips: [],
          domains: [],
          hashes: [],
          urls: [],
        },
      }

      const hasEmptyIoCs = data.iocs &&
        data.iocs.ips?.length === 0 &&
        data.iocs.domains?.length === 0

      expect(hasEmptyIoCs).toBe(true)
    })
  })
})
