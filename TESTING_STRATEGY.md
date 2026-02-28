# Testing Strategy for Maritime Cyber Project

## Overview

This document outlines a comprehensive testing strategy for the maritime cybersecurity project, covering Python scripts (CVE Monitor, OSINT Collector) and the Next.js dashboard application. The strategy includes test setup, coverage targets, specific test cases, and implementation roadmap.

## Current State

- **No test suite exists** across the entire project
- **No test dependencies** are configured in either Python or Node.js environments
- **Critical logic** in data collection, API endpoints, and components lacks test coverage
- **Manual verification** is currently the only quality assurance method

## Testing Goals

1. **Achieve 80%+ code coverage** on critical paths (data validation, API handlers, core logic)
2. **Prevent regressions** in data collection and API functionality
3. **Ensure data integrity** across ingestion pipeline
4. **Validate security** of API endpoints and authentication
5. **Improve maintainability** through documented, testable code

---

## Phase 1: Foundation (Priority: High)

### 1.1 Python Testing Setup

#### Dependencies to Add

```bash
# Update requirements.txt with test dependencies
pytest>=7.4.0
pytest-mock>=3.11.0
pytest-cov>=4.1.0
responses>=0.23.0  # Mock HTTP requests
```

#### Test Structure

```
maritime-cyber/
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # Shared fixtures
│   ├── unit/
│   │   ├── test_cve_monitor.py
│   │   └── test_osint_collector.py
│   ├── integration/
│   │   ├── test_cve_data_pipeline.py
│   │   └── test_osint_pipeline.py
│   └── fixtures/
│       ├── sample_cve_responses.json
│       └── sample_osint_responses.json
```

#### Pytest Configuration (`pytest.ini`)

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = --cov=. --cov-report=html --cov-report=term-missing --cov-threshold=80
```

#### Core Test Cases for cve-monitor.py

**Unit Tests:**
- Test CVE data parsing from NVD API responses
- Test maritime keyword matching logic
- Test vendor filtering and deduplication
- Test severity level classification
- Test date filtering and range selection
- Test IoC extraction (IPs, domains, hashes)
- Test file I/O operations (saving CVE database)
- Test error handling for network failures
- Test missing or malformed API responses
- Test command-line argument parsing

**Integration Tests:**
- Full CVE collection pipeline with mocked API
- Data persistence and retrieval from files
- Multiple source coordination (NVD, CISA KEV, CVE.org)
- Report generation from collected data

**Example Test:**
```python
def test_maritime_keyword_matching(mock_cve_data):
    """Test that maritime-specific CVEs are correctly identified"""
    cves = parse_cve_database(mock_cve_data)
    maritime_cves = filter_maritime_cves(cves)

    assert len(maritime_cves) > 0
    assert any('ECDIS' in cve['description'] for cve in maritime_cves)
    assert any('AIS' in cve['description'] for cve in maritime_cves)
```

#### Core Test Cases for osint-collector.py

**Unit Tests:**
- Test RSS feed parsing and validation
- Test HTML parsing with BeautifulSoup
- Test defanging URLs and IoCs
- Test data normalization and deduplication
- Test source-specific parsers (ransomware.live, pastebin, etc.)
- Test maritime threat filtering
- Test JSON export formatting
- Test error handling for timeout and connection errors
- Test rate limiting and request throttling
- Test credential handling (API keys, headers)

**Integration Tests:**
- Full OSINT collection from multiple sources with mocked responses
- Data aggregation and merging
- De-duplication across sources
- Export pipeline (JSON, markdown)

**Example Test:**
```python
def test_ransomware_group_extraction(mock_ransomware_response):
    """Test extraction of ransomware group information"""
    groups = parse_ransomware_feed(mock_ransomware_response)

    assert len(groups) > 0
    assert all('name' in g for g in groups)
    assert all('victims' in g for g in groups)
```

---

### 1.2 Next.js API Route Testing

#### Dependencies to Add

```json
{
  "devDependencies": {
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "@testing-library/react": "^14.0.0",
    "@testing-library/jest-dom": "^6.0.0",
    "@testing-library/user-event": "^14.0.0"
  }
}
```

#### Jest Configuration (`jest.config.ts`)

```typescript
import type { Config } from 'jest'

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts', '**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.tsx',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
}

export default config
```

#### Test Structure

```
maritime-cyber-dashboard/
├── src/
│   └── __tests__/
│       ├── api/
│       │   └── ingest.test.ts
│       └── components/
│           ├── dashboard.test.tsx
│           └── incident-table.test.tsx
```

#### Core Test Cases for API Routes

**Authentication Tests (`/api/ingest`):**
- Valid API key in `x-api-key` header → 200 response
- Valid API key in `Authorization: Bearer` header → 200 response
- Missing API key → 401 Unauthorized
- Invalid/malformed API key → 401 Unauthorized
- No `INGEST_API_KEY` configured → allows all requests (with warning)

**Payload Validation Tests:**
- Valid incident payload → 200 with inserted data
- Valid maritime_asset payload → 200 with upserted data
- Valid threat_group payload → 200 with upserted data
- Missing required `type` field → 400 Bad Request
- Missing required `data` field → 400 Bad Request
- Invalid `type` value → 400 Bad Request with error message
- Empty data object → 400 Bad Request

**Type-Specific Tests:**

*Incident Ingestion:*
- Title is required and non-empty
- Severity matches allowed values: Critical, High, Medium, Low
- Sector matches maritime sectors (Maritime, Energy, Transportation, etc.)
- Attack_vector matches known vectors (Ransomware, Phishing, etc.)
- Optional fields (threat_group, target_organization, iocs) handled correctly
- IoCs structure validation (ips, domains, hashes, urls are arrays)

*Maritime Asset Ingestion:*
- Name is required and unique (upsert on name)
- Asset_type matches allowed types: Port, Vessel, Terminal, Offshore Platform, Shipping Company
- Exposure_score defaults to 0 if not provided
- Vulnerabilities array contains valid CVE objects
- last_scan timestamp is set to current time

*Threat Group Ingestion:*
- Name is required and unique (upsert on name)
- Active field defaults to true if not provided
- victim_count defaults to 0 if not provided
- last_activity defaults to current time if not provided
- TTPs array is properly stored

**Error Handling Tests:**
- Supabase connection failure → 500 error with message
- Database insert error → 500 error with details
- JSON parsing error (malformed payload) → 400 error
- Missing environment variables → 500 with configuration message

**Health Check Tests (`GET /api/ingest`):**
- Returns 200 status
- Includes endpoint documentation
- Includes example payloads for all types

**Example Test:**
```typescript
describe('POST /api/ingest', () => {
  it('should reject request with invalid API key', async () => {
    const response = await fetch('/api/ingest', {
      method: 'POST',
      headers: { 'x-api-key': 'invalid-key' },
      body: JSON.stringify({
        type: 'incident',
        data: { title: 'Test' }
      })
    })

    expect(response.status).toBe(401)
    const data = await response.json()
    expect(data.error).toBe('Unauthorized')
  })

  it('should insert valid incident', async () => {
    const response = await fetch('/api/ingest', {
      method: 'POST',
      headers: { 'x-api-key': process.env.INGEST_API_KEY },
      body: JSON.stringify({
        type: 'incident',
        data: {
          title: 'Ransomware Attack',
          severity: 'Critical',
          sector: 'Maritime',
          attack_vector: 'Ransomware'
        }
      })
    })

    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.success).toBe(true)
    expect(data.data.id).toBeDefined()
  })
})
```

---

## Phase 2: Component Testing (Priority: Medium)

### 2.1 React Component Tests

#### Dependencies (already included in Phase 1)

#### Test Structure

```
maritime-cyber-dashboard/src/__tests__/components/
├── dashboard.test.tsx
├── incident-table.test.tsx
├── maritime-assets.test.tsx
└── threat-groups.test.tsx
```

#### Core Test Cases

**Dashboard Component:**
- Renders without crashing
- Displays incident count correctly
- Updates when new data arrives
- Responsive layout on mobile/tablet/desktop
- Navigation between tabs works
- Loading states display correctly
- Error states show appropriate messages

**Incident Table:**
- Renders all incidents from props
- Sorting by severity, date, sector works
- Filtering by severity level works
- Pagination displays correct items
- Click handlers trigger navigation
- Empty state displays when no data
- Large datasets don't cause performance issues

**Maritime Assets Card:**
- Displays asset information correctly
- Shows exposure score visualization
- Lists vulnerabilities properly
- Updates when props change

**Example Test:**
```typescript
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Dashboard from '@/app/(dashboard)/dashboard/page'

describe('Dashboard Component', () => {
  it('should render incident count', () => {
    render(<Dashboard incidents={mockIncidents} />)
    expect(screen.getByText('Critical Incidents: 3')).toBeInTheDocument()
  })

  it('should filter incidents by severity', async () => {
    render(<Dashboard incidents={mockIncidents} />)
    const criticalFilter = screen.getByRole('button', { name: /critical/i })

    await userEvent.click(criticalFilter)

    const table = screen.getByRole('table')
    expect(table.querySelectorAll('tr')).toHaveLength(4) // header + 3 rows
  })
})
```

---

## Phase 3: Integration & End-to-End (Priority: Medium)

### 3.1 Integration Testing

#### Test Approach

- **Database Integration**: Test with Supabase test database
- **API to Database**: Full flow from ingest endpoint to database
- **Data Pipeline**: Python scripts → API → Dashboard visualization

#### Key Integration Tests

1. **Data Ingestion Pipeline**
   - OSINT collection → API endpoint → Supabase → Dashboard
   - Verify data transformations maintain integrity
   - Test concurrent ingestion requests
   - Verify deduplication logic

2. **CVE Monitoring Pipeline**
   - CVE collection → Data enrichment → Report generation
   - Test maritime-specific filtering at each stage
   - Verify threat intelligence correlation

3. **Cross-Service Communication**
   - API authentication flows
   - Environment variable configuration
   - Error propagation and logging

### 3.2 End-to-End Testing (Future)

```json
{
  "devDependencies": {
    "playwright": "^1.40.0",
    "e2e": "^1.0.0"
  }
}
```

**E2E Test Scenarios (Playwright):**
1. User logs in → navigates to dashboard → views incidents
2. Admin submits incident via API → appears in dashboard within 5s
3. Filter maritime incidents → displays only maritime sector
4. Sort by severity → shows critical incidents first
5. Export report → downloads valid JSON file

---

## Coverage Targets

### Python Scripts

| Module | Current | Target | Priority |
|--------|---------|--------|----------|
| cve-monitor.py | 0% | 85% | High |
| osint-collector.py | 0% | 85% | High |
| Data parsing | 0% | 95% | Critical |
| Error handling | 0% | 90% | High |
| Integration | 0% | 70% | Medium |

### Next.js Application

| Area | Current | Target | Priority |
|------|---------|--------|----------|
| API Routes | 0% | 90% | Critical |
| Components | 0% | 75% | Medium |
| Type validation | 0% | 95% | High |
| Error handling | 0% | 85% | High |

---

## Implementation Roadmap

### Week 1-2: Setup & Python Foundation
- [ ] Add pytest, pytest-mock, responses to requirements.txt
- [ ] Create tests/ directory structure
- [ ] Write conftest.py with shared fixtures
- [ ] Create mock data files (sample CVE/OSINT responses)
- [ ] Write 20+ unit tests for cve-monitor.py core functions
- [ ] Write 20+ unit tests for osint-collector.py core functions
- [ ] Achieve 80% coverage on Python code

### Week 3-4: API Route Testing
- [ ] Add Jest and testing dependencies to package.json
- [ ] Create jest.config.ts
- [ ] Write authentication tests for /api/ingest
- [ ] Write payload validation tests
- [ ] Write type-specific ingestion tests
- [ ] Write error handling tests
- [ ] Achieve 90% coverage on API routes

### Week 5-6: Component Testing
- [ ] Write tests for Dashboard component
- [ ] Write tests for Incident table/list
- [ ] Write tests for Maritime assets display
- [ ] Write tests for Threat group display
- [ ] Test responsive layouts
- [ ] Achieve 75% coverage on components

### Week 7-8: Integration Testing
- [ ] Set up test Supabase instance
- [ ] Write end-to-end data pipeline tests
- [ ] Test CVE to report generation
- [ ] Test OSINT to dashboard flow
- [ ] Performance testing with large datasets

### Week 9+: Continuous Improvement
- [ ] E2E tests with Playwright
- [ ] CI/CD pipeline integration
- [ ] Automated test reporting
- [ ] Performance benchmarks

---

## Running Tests

### Python Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/unit/test_cve_monitor.py

# Run with verbose output
pytest -v

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/
```

### Next.js Tests

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Run in watch mode
npm test -- --watch

# Run specific test file
npm test -- api/ingest.test.ts
```

---

## Test Data & Fixtures

### Python Fixtures

Create `tests/fixtures/sample_responses.json`:
```json
{
  "nvd_cve_response": {
    "resultIndex": 0,
    "totalResults": 1,
    "result": {
      "CVE_Items": [
        {
          "cve": {
            "CVE_data_meta": { "ID": "CVE-2024-0001" },
            "description": { "description_data": [{ "value": "ECDIS vulnerability" }] }
          },
          "impact": { "baseMetricV3": { "cvssV3": { "baseSeverity": "CRITICAL" } } }
        }
      ]
    }
  },
  "cisa_kev_response": [...],
  "ransomware_live_response": [...]
}
```

### TypeScript Fixtures

Create mock data factories:
```typescript
// __tests__/fixtures/incident.ts
export const mockIncident = {
  id: '123',
  title: 'Test Incident',
  severity: 'Critical',
  sector: 'Maritime',
  attack_vector: 'Ransomware',
  created_at: new Date().toISOString(),
}
```

---

## CI/CD Integration

### GitHub Actions Workflow (`.github/workflows/test.yml`)

```yaml
name: Tests

on: [push, pull_request]

jobs:
  python-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest --cov=. --cov-report=xml
      - uses: codecov/codecov-action@v3

  node-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm test -- --coverage
      - uses: codecov/codecov-action@v3
```

---

## Test Best Practices

1. **Naming**: Use descriptive test names that explain what is being tested
   - ✅ `test_maritime_keyword_matching_identifies_ecdis_systems`
   - ❌ `test_keywords`

2. **Isolation**: Each test should be independent
   - Use fixtures/mocks to avoid external dependencies
   - Clean up after tests
   - Don't rely on test execution order

3. **Assertions**: Keep assertions focused and meaningful
   - One logical assertion per test
   - Provide helpful error messages
   - Avoid assertion overkill

4. **Mocking**: Mock external services (APIs, databases)
   - Use `responses` library for HTTP mocking
   - Use `pytest-mock` for function mocking
   - Keep mocks realistic

5. **Coverage**: Aim for high coverage but focus on critical paths
   - 80%+ on core logic
   - 100% on data validation
   - 70%+ on components

---

## Handling Sensitive Data in Tests

1. **Never commit real API keys or credentials**
2. **Use environment variables with `.env.test`**
3. **Mock sensitive endpoints in tests**
4. **Sanitize test data (remove real IPs, domains)**
5. **Review test fixtures for accidental secrets**

Example:
```python
# Use pytest fixtures with environment mocking
@pytest.fixture
def mock_api_key(monkeypatch):
    monkeypatch.setenv('INGEST_API_KEY', 'test-key-12345')
    yield
```

---

## Maintenance & Monitoring

### Test Health Metrics

Track these metrics over time:
- **Test Coverage**: Target 80%+ overall
- **Test Execution Time**: Keep under 5 minutes for full suite
- **Flakiness Rate**: Should be < 1%
- **Pass Rate**: Target 100%

### Regular Reviews

- Monthly: Review test coverage and identify gaps
- Quarterly: Refactor and consolidate tests
- Annually: Update testing strategy based on project growth

---

## Resources

### Testing Libraries
- [pytest Documentation](https://docs.pytest.org/)
- [Jest Documentation](https://jestjs.io/)
- [React Testing Library](https://testing-library.com/react)
- [Responses Library](https://github.com/getsentry/responses)

### Maritime Security Context
- Ensure tests cover maritime-specific IoCs and threat vectors
- Validate against real-world incident patterns
- Include maritime sector vulnerabilities (ECDIS, AIS, VSAT, etc.)

---

## Approval & Sign-off

This testing strategy should be reviewed and approved by:
- [ ] Development Lead
- [ ] Security Lead
- [ ] Project Manager

**Approval Date**: ________________
**Next Review Date**: ________________
