"""
Shared pytest fixtures for maritime cyber project tests.
"""
import pytest
import json
from pathlib import Path


@pytest.fixture
def sample_cve_response():
    """Mock NVD CVE API response"""
    return {
        "resultIndex": 0,
        "totalResults": 2,
        "result": {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2024-0001"},
                        "description": {
                            "description_data": [
                                {
                                    "value": "ECDIS (Electronic Chart Display Information System) vulnerability affecting maritime navigation systems"
                                }
                            ]
                        },
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "baseSeverity": "CRITICAL",
                                "baseScore": 9.8
                            }
                        }
                    },
                    "publishedDate": "2024-01-15T00:00Z"
                },
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2024-0002"},
                        "description": {
                            "description_data": [
                                {
                                    "value": "AIS (Automatic Identification System) authentication bypass in maritime vessel tracking"
                                }
                            ]
                        },
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "baseSeverity": "HIGH",
                                "baseScore": 8.2
                            }
                        }
                    },
                    "publishedDate": "2024-01-20T00:00Z"
                },
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2024-0003"},
                        "description": {
                            "description_data": [
                                {
                                    "value": "Generic web application vulnerability unrelated to maritime"
                                }
                            ]
                        },
                    },
                    "impact": {
                        "baseMetricV3": {
                            "cvssV3": {
                                "baseSeverity": "MEDIUM",
                                "baseScore": 5.0
                            }
                        }
                    },
                    "publishedDate": "2024-01-10T00:00Z"
                }
            ]
        }
    }


@pytest.fixture
def sample_ransomware_response():
    """Mock ransomware.live API response"""
    return [
        {
            "post_title": "Port of Rotterdam",
            "group_name": "LockBit3",
            "post_date": "2024-01-20",
            "ransom_amount": "$5000000",
            "description": "Major European maritime port attacked"
        },
        {
            "post_title": "Shipping Company Alpha",
            "group_name": "Akira",
            "post_date": "2024-01-18",
            "ransom_amount": "$2000000",
            "description": "Maritime logistics company compromised"
        },
        {
            "post_title": "Generic Corp",
            "group_name": "BlackCat",
            "post_date": "2024-01-19",
            "ransom_amount": "$1000000",
            "description": "Non-maritime company"
        }
    ]


@pytest.fixture
def sample_maritime_keywords():
    """Maritime-specific keywords for testing"""
    return [
        "ECDIS", "electronic chart", "navigation system", "GPS marine",
        "AIS", "automatic identification system", "radar marine",
        "VSAT", "satellite marine", "Inmarsat", "Iridium",
        "ship automation", "vessel control", "marine SCADA",
        "port automation", "terminal operating system", "TOS",
        "Kongsberg Maritime", "Wärtsilä", "Furuno", "JRC", "Raymarine"
    ]


@pytest.fixture
def sample_incident_payload():
    """Sample incident for API testing"""
    return {
        "type": "incident",
        "data": {
            "title": "Ransomware Attack on Port Terminal",
            "description": "LockBit3 ransomware deployed on SCADA systems",
            "threat_group": "LockBit3",
            "severity": "Critical",
            "sector": "Maritime",
            "attack_vector": "Ransomware",
            "target_organization": "Port Authority",
            "target_country": "Netherlands",
            "iocs": {
                "ips": ["192.168.1.100", "10.0.0.50"],
                "domains": ["evil[.]com", "c2[.]net"],
                "hashes": ["5d41402abc4b2a76b9719d911017c592"],
                "urls": ["http://malware[.]site/payload"]
            },
            "source_url": "https://example.com/incident"
        }
    }


@pytest.fixture
def sample_maritime_asset_payload():
    """Sample maritime asset for API testing"""
    return {
        "type": "maritime_asset",
        "data": {
            "name": "Port of Los Angeles",
            "asset_type": "Port",
            "country": "USA",
            "exposure_score": 75,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-0001",
                    "severity": "Critical",
                    "description": "ECDIS vulnerability"
                }
            ]
        }
    }


@pytest.fixture
def sample_threat_group_payload():
    """Sample threat group for API testing"""
    return {
        "type": "threat_group",
        "data": {
            "name": "LockBit3",
            "description": "Ransomware-as-a-Service group targeting maritime",
            "ttps": ["Spear Phishing", "Lateral Movement", "Data Exfiltration"],
            "victim_count": 145,
            "last_activity": "2024-01-20T12:00:00Z",
            "active": True
        }
    }


@pytest.fixture
def mock_api_key(monkeypatch):
    """Set mock API key for testing"""
    test_key = "test-api-key-12345"
    monkeypatch.setenv("INGEST_API_KEY", test_key)
    return test_key


@pytest.fixture
def invalid_payloads():
    """Collection of invalid payloads for negative testing"""
    return [
        # Missing type
        {"data": {"title": "Test"}},
        # Missing data
        {"type": "incident"},
        # Invalid type
        {"type": "invalid_type", "data": {}},
        # Empty data
        {"type": "incident", "data": {}},
        # Null data
        {"type": "incident", "data": None},
    ]


@pytest.fixture
def maritime_keywords_list():
    """List of maritime-related keywords for filtering tests"""
    return [
        "ECDIS", "electronic chart", "AIS", "VSAT", "GMDSS",
        "ship automation", "vessel control", "port automation",
        "TOS", "crane control", "Kongsberg", "Wärtsilä",
        "marine SCADA", "maritime ICS"
    ]
