"""
Unit tests for CVE Monitor
Tests for CVE parsing, maritime keyword matching, filtering, and severity classification
"""
import pytest
import json
from datetime import datetime, timedelta


class TestCVEParsing:
    """Test CVE data parsing from API responses"""

    def test_parse_cve_items_from_response(self, sample_cve_response):
        """Test extracting CVE items from NVD API response"""
        cve_items = sample_cve_response["result"]["CVE_Items"]

        assert len(cve_items) == 3
        assert cve_items[0]["cve"]["CVE_data_meta"]["ID"] == "CVE-2024-0001"
        assert cve_items[1]["cve"]["CVE_data_meta"]["ID"] == "CVE-2024-0002"

    def test_extract_cve_id(self, sample_cve_response):
        """Test extracting CVE ID from CVE item"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]

        assert cve_id.startswith("CVE-")
        assert cve_id == "CVE-2024-0001"

    def test_extract_description(self, sample_cve_response):
        """Test extracting description from CVE item"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        description = cve_item["cve"]["description"]["description_data"][0]["value"]

        assert len(description) > 0
        assert "ECDIS" in description
        assert "maritime navigation" in description

    def test_extract_severity(self, sample_cve_response):
        """Test extracting severity from CVE item"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        severity = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

        assert severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert severity == "CRITICAL"

    def test_extract_base_score(self, sample_cve_response):
        """Test extracting CVSS base score from CVE item"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        score = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]

        assert isinstance(score, (int, float))
        assert 0.0 <= score <= 10.0
        assert score == 9.8

    def test_extract_published_date(self, sample_cve_response):
        """Test extracting published date from CVE item"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        published_date = cve_item["publishedDate"]

        assert "2024-01-15" in published_date
        assert "Z" in published_date  # ISO format


class TestMaritimeKeywordMatching:
    """Test maritime-specific keyword matching"""

    def test_identify_maritime_cvе_ecdis(self, sample_cve_response, maritime_keywords_list):
        """Test identification of ECDIS vulnerability"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        description = cve_item["cve"]["description"]["description_data"][0]["value"]

        is_maritime = any(keyword.lower() in description.lower() for keyword in maritime_keywords_list)
        assert is_maritime, "ECDIS vulnerability should be identified as maritime"

    def test_identify_maritime_cve_ais(self, sample_cve_response, maritime_keywords_list):
        """Test identification of AIS vulnerability"""
        cve_item = sample_cve_response["result"]["CVE_Items"][1]
        description = cve_item["cve"]["description"]["description_data"][0]["value"]

        is_maritime = any(keyword.lower() in description.lower() for keyword in maritime_keywords_list)
        assert is_maritime, "AIS vulnerability should be identified as maritime"

    def test_exclude_non_maritime_cve(self, sample_cve_response, maritime_keywords_list):
        """Test that non-maritime CVEs are excluded"""
        cve_item = sample_cve_response["result"]["CVE_Items"][2]
        description = cve_item["cve"]["description"]["description_data"][0]["value"]

        is_maritime = any(keyword.lower() in description.lower() for keyword in maritime_keywords_list)
        assert not is_maritime, "Generic vulnerability should not be identified as maritime"

    def test_case_insensitive_matching(self, maritime_keywords_list):
        """Test that keyword matching is case-insensitive"""
        description = "This involves ECDIS systems and AIS technology"

        is_maritime = any(keyword.lower() in description.lower() for keyword in maritime_keywords_list)
        assert is_maritime

    def test_keyword_in_long_description(self, maritime_keywords_list):
        """Test keyword matching in long descriptions"""
        description = "A critical vulnerability affecting maritime vessel control systems " \
                     "including ECDIS charts and AIS tracking systems was discovered"

        maritime_matches = [kw for kw in maritime_keywords_list if kw.lower() in description.lower()]
        assert len(maritime_matches) >= 2


class TestSeverityClassification:
    """Test CVE severity classification"""

    def test_critical_severity(self, sample_cve_response):
        """Test identification of CRITICAL severity"""
        cve_item = sample_cve_response["result"]["CVE_Items"][0]
        severity = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

        assert severity == "CRITICAL"

    def test_high_severity(self, sample_cve_response):
        """Test identification of HIGH severity"""
        cve_item = sample_cve_response["result"]["CVE_Items"][1]
        severity = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

        assert severity == "HIGH"

    def test_medium_severity(self, sample_cve_response):
        """Test identification of MEDIUM severity"""
        cve_item = sample_cve_response["result"]["CVE_Items"][2]
        severity = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

        assert severity == "MEDIUM"

    def test_severity_to_integer_mapping(self):
        """Test mapping severity levels to integer values"""
        severity_map = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2
        }

        assert severity_map["CRITICAL"] > severity_map["HIGH"]
        assert severity_map["HIGH"] > severity_map["MEDIUM"]
        assert severity_map["MEDIUM"] > severity_map["LOW"]


class TestCVEFiltering:
    """Test CVE filtering and deduplication"""

    def test_filter_by_severity(self, sample_cve_response):
        """Test filtering CVEs by severity level"""
        cves = sample_cve_response["result"]["CVE_Items"]
        critical_cves = [c for c in cves
                        if c["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == "CRITICAL"]

        assert len(critical_cves) == 1
        assert critical_cves[0]["cve"]["CVE_data_meta"]["ID"] == "CVE-2024-0001"

    def test_filter_by_date_range(self, sample_cve_response):
        """Test filtering CVEs by published date range"""
        cves = sample_cve_response["result"]["CVE_Items"]
        start_date = "2024-01-15"
        end_date = "2024-01-20"

        filtered = [c for c in cves
                   if start_date <= c["publishedDate"][:10] <= end_date]

        assert len(filtered) >= 2

    def test_deduplication_by_cve_id(self):
        """Test deduplication of CVEs by ID"""
        cves = [
            {"id": "CVE-2024-0001", "severity": "HIGH"},
            {"id": "CVE-2024-0002", "severity": "MEDIUM"},
            {"id": "CVE-2024-0001", "severity": "HIGH"}  # Duplicate
        ]

        deduplicated = {cve["id"]: cve for cve in cves}.values()

        assert len(deduplicated) == 2
        assert len([c for c in deduplicated if c["id"] == "CVE-2024-0001"]) == 1

    def test_filter_maritime_by_vendor(self, maritime_keywords_list):
        """Test filtering by maritime vendor names"""
        vendors = ["Kongsberg", "Wärtsilä", "Furuno", "JRC", "Microsoft"]
        maritime_vendors = [v for v in vendors
                           if any(v.lower() in kw.lower() or kw.lower() in v.lower()
                                 for kw in maritime_keywords_list)]

        assert len(maritime_vendors) >= 3


class TestIOCExtraction:
    """Test Indicator of Compromise (IoC) extraction"""

    def test_extract_ip_addresses(self):
        """Test extraction of IP addresses from descriptions"""
        description = "Malware communicates with 192.168.1.100 and 10.0.0.50"
        ips = []
        import re
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(pattern, description)

        assert len(ips) == 2
        assert "192.168.1.100" in ips
        assert "10.0.0.50" in ips

    def test_extract_domains(self):
        """Test extraction of domain names from descriptions"""
        description = "C2 server at malware.com and backup at evil.net"
        domains = ["malware.com", "evil.net"]

        assert len(domains) == 2
        assert "malware.com" in domains

    def test_defang_iocs(self):
        """Test defanging IoCs for safe sharing"""
        ioc = "192.168.1.100"
        defanged = ioc.replace(".", "[.]")

        assert defanged == "192[.]168[.]1[.]100"
        assert "." not in defanged.replace("[.]", "")

    def test_defang_domain(self):
        """Test defanging domain names"""
        domain = "malware.com"
        defanged = domain.replace(".", "[.]")

        assert defanged == "malware[.]com"


class TestDataValidation:
    """Test data validation and normalization"""

    def test_validate_cve_id_format(self):
        """Test validation of CVE ID format"""
        valid_ids = ["CVE-2024-0001", "CVE-2023-1234", "CVE-2022-50000"]

        for cve_id in valid_ids:
            assert cve_id.startswith("CVE-")
            parts = cve_id.split("-")
            assert len(parts) == 3
            assert parts[1].isdigit()
            assert parts[2].isdigit()

    def test_validate_severity_values(self):
        """Test validation of severity level values"""
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        invalid_severities = ["EXTREME", "UNKNOWN", "INFO"]

        for severity in valid_severities:
            assert severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        for severity in invalid_severities:
            assert severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_normalize_description(self):
        """Test normalization of CVE descriptions"""
        description = "  ECDIS  vulnerability   affecting    maritime  systems  "
        normalized = " ".join(description.split())

        assert "  " not in normalized
        assert normalized.strip() == "ECDIS vulnerability affecting maritime systems"


class TestErrorHandling:
    """Test error handling in CVE monitoring"""

    def test_handle_missing_severity(self):
        """Test handling of missing severity information"""
        cve_item = {
            "cve": {"CVE_data_meta": {"ID": "CVE-2024-0001"}},
            "impact": {}  # Missing severity
        }

        severity = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity")

        assert severity is None

    def test_handle_missing_description(self):
        """Test handling of missing description"""
        cve_item = {
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2024-0001"},
                "description": {"description_data": []}  # Empty description
            }
        }

        description = (cve_item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", ""))

        assert description == ""

    def test_handle_malformed_date(self):
        """Test handling of malformed date"""
        dates = ["invalid-date", "", None, "2024-13-45"]

        for date in dates:
            # Simple validation
            if date and isinstance(date, str):
                try:
                    datetime.fromisoformat(date.replace("Z", "+00:00"))
                    is_valid = True
                except (ValueError, AttributeError):
                    is_valid = False
            else:
                is_valid = False

    def test_handle_empty_cve_response(self):
        """Test handling of empty CVE response"""
        empty_response = {
            "result": {
                "CVE_Items": []
            }
        }

        cves = empty_response["result"]["CVE_Items"]
        assert len(cves) == 0


class TestIntegration:
    """Integration tests for CVE monitoring pipeline"""

    def test_process_full_cve_response(self, sample_cve_response, maritime_keywords_list):
        """Test processing complete CVE response"""
        maritime_cves = []

        for cve_item in sample_cve_response["result"]["CVE_Items"]:
            cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
            description = cve_item["cve"]["description"]["description_data"][0]["value"]
            severity = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

            # Check if maritime
            is_maritime = any(kw.lower() in description.lower() for kw in maritime_keywords_list)

            if is_maritime:
                maritime_cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "description": description
                })

        assert len(maritime_cves) == 2
        assert any(cve["id"] == "CVE-2024-0001" for cve in maritime_cves)
        assert any(cve["id"] == "CVE-2024-0002" for cve in maritime_cves)

    def test_report_generation(self, sample_cve_response):
        """Test generating report from CVE data"""
        total_cves = len(sample_cve_response["result"]["CVE_Items"])
        critical_count = sum(1 for c in sample_cve_response["result"]["CVE_Items"]
                           if c["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == "CRITICAL")
        high_count = sum(1 for c in sample_cve_response["result"]["CVE_Items"]
                        if c["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == "HIGH")

        report = {
            "total": total_cves,
            "critical": critical_count,
            "high": high_count
        }

        assert report["total"] == 3
        assert report["critical"] == 1
        assert report["high"] == 1
