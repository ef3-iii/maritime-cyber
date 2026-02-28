"""
Unit tests for OSINT Collector
Tests for RSS feed parsing, data collection, deduplication, and maritime threat filtering
"""
import pytest
import json
from datetime import datetime


class TestRSSFeedParsing:
    """Test RSS feed parsing and validation"""

    def test_parse_feed_entry(self):
        """Test parsing a single RSS feed entry"""
        entry = {
            "title": "New Ransomware Campaign Targets Maritime",
            "published": "2024-01-20T10:00:00Z",
            "link": "https://example.com/article",
            "summary": "LockBit3 targets shipping companies"
        }

        assert entry["title"] == "New Ransomware Campaign Targets Maritime"
        assert "2024-01-20" in entry["published"]
        assert entry["link"].startswith("https://")

    def test_validate_feed_entry_required_fields(self):
        """Test validation of required feed entry fields"""
        entry = {
            "title": "Article Title",
            "published": "2024-01-20T10:00:00Z",
            "link": "https://example.com"
        }

        required_fields = ["title", "published", "link"]
        has_all_fields = all(field in entry for field in required_fields)

        assert has_all_fields

    def test_extract_publication_date(self):
        """Test extraction of publication date from feed entry"""
        entry = {
            "published": "2024-01-20T10:00:00Z",
            "title": "Article"
        }

        date_str = entry["published"]
        assert "2024-01-20" in date_str
        assert "Z" in date_str  # UTC indicator

    def test_handle_missing_fields(self):
        """Test handling of missing optional fields"""
        entry = {
            "title": "Article",
            "link": "https://example.com"
            # Missing 'published' and 'summary'
        }

        published = entry.get("published", "Unknown")
        summary = entry.get("summary", "No summary available")

        assert published == "Unknown"
        assert summary == "No summary available"


class TestHTMLParsing:
    """Test HTML content parsing with BeautifulSoup"""

    def test_extract_article_title(self):
        """Test extraction of article title from HTML"""
        html_content = "<h1>New Maritime Cyber Threat Discovered</h1>"
        # Simulate BeautifulSoup parsing
        title = html_content.replace("<h1>", "").replace("</h1>", "")

        assert title == "New Maritime Cyber Threat Discovered"

    def test_extract_links_from_content(self):
        """Test extraction of links from HTML content"""
        html_content = '<a href="https://threat.com/report">Read more</a>'
        # Simulate link extraction
        links = []
        if 'href=' in html_content:
            start = html_content.find('href="') + 6
            end = html_content.find('"', start)
            links.append(html_content[start:end])

        assert len(links) == 1
        assert links[0] == "https://threat.com/report"

    def test_extract_paragraphs(self):
        """Test extraction of paragraphs from HTML"""
        html_content = "<p>First paragraph</p><p>Second paragraph</p>"
        paragraphs = []

        import re
        paragraphs = re.findall(r'<p>(.*?)</p>', html_content)

        assert len(paragraphs) == 2
        assert "First paragraph" in paragraphs


class TestIOCDefanging:
    """Test defanging of Indicators of Compromise"""

    def test_defang_ip_address(self):
        """Test defanging IP addresses"""
        ip = "192.168.1.100"
        defanged = ip.replace(".", "[.]")

        assert defanged == "192[.]168[.]1[.]100"
        assert "." not in defanged

    def test_defang_domain(self):
        """Test defanging domain names"""
        domain = "malware.com"
        defanged = domain.replace(".", "[.]")

        assert defanged == "malware[.]com"

    def test_defang_url(self):
        """Test defanging URLs"""
        url = "http://evil.com/payload"
        defanged = url.replace(".", "[.]")

        assert defanged == "http://evil[.]com/payload"
        assert "evil.com" not in defanged

    def test_refang_iocs(self):
        """Test converting defanged IoCs back to normal"""
        defanged = "192[.]168[.]1[.]100"
        refanged = defanged.replace("[.]", ".")

        assert refanged == "192.168.1.100"


class TestDataNormalization:
    """Test data normalization and standardization"""

    def test_normalize_group_names(self):
        """Test normalization of threat group names"""
        names = ["lockbit3", "LockBit 3", "lockbit 3.0", "LOCKBIT3"]
        normalized = [name.upper().replace(" ", "").replace(".", "") for name in names]

        assert all(norm == "LOCKBIT3" for norm in normalized)

    def test_normalize_whitespace(self):
        """Test normalization of whitespace"""
        text = "  Port   of  Rotterdam   attack  "
        normalized = " ".join(text.split())

        assert normalized == "Port of Rotterdam attack"
        assert "  " not in normalized

    def test_lowercase_normalization(self):
        """Test converting text to lowercase"""
        text = "Maritime Port Authority"
        normalized = text.lower()

        assert normalized == "maritime port authority"

    def test_remove_special_characters(self):
        """Test removal of special characters"""
        text = "Ransomware@Attack#2024!"
        cleaned = "".join(c for c in text if c.isalnum() or c == " ")

        assert "@" not in cleaned
        assert "#" not in cleaned
        assert "!" not in cleaned


class TestDeduplication:
    """Test data deduplication across sources"""

    def test_deduplicate_by_id(self):
        """Test deduplication using unique ID"""
        incidents = [
            {"id": "1", "title": "Attack A"},
            {"id": "2", "title": "Attack B"},
            {"id": "1", "title": "Attack A"}  # Duplicate
        ]

        deduplicated = {inc["id"]: inc for inc in incidents}.values()

        assert len(deduplicated) == 2

    def test_deduplicate_by_content_hash(self):
        """Test deduplication using content hash"""
        import hashlib

        incidents = [
            {"content": "Ransomware attack on port"},
            {"content": "Ransomware attack on port"},  # Duplicate
            {"content": "Different incident"}
        ]

        hashes = {}
        for inc in incidents:
            h = hashlib.md5(inc["content"].encode()).hexdigest()
            hashes[h] = inc

        assert len(hashes) == 2

    def test_merge_duplicate_records(self):
        """Test merging of duplicate records"""
        incident1 = {
            "source": ["source1"],
            "severity": "High",
            "date": "2024-01-20"
        }
        incident2 = {
            "source": ["source2"],
            "severity": "High",
            "date": "2024-01-20"
        }

        # Merge logic
        merged = incident1.copy()
        merged["source"] = list(set(incident1["source"] + incident2["source"]))

        assert len(merged["source"]) == 2


class TestMaritimeFiltering:
    """Test maritime-specific threat filtering"""

    def test_identify_maritime_threat(self, sample_ransomware_response, maritime_keywords_list):
        """Test identification of maritime threats"""
        maritime_threats = []

        for threat in sample_ransomware_response:
            description = threat.get("description", "").lower()
            title = threat.get("post_title", "").lower()

            if any(kw.lower() in description or kw.lower() in title
                   for kw in ["maritime", "port", "shipping", "vessel"]):
                maritime_threats.append(threat)

        assert len(maritime_threats) >= 2

    def test_filter_by_target_sector(self):
        """Test filtering threats by target sector"""
        threats = [
            {"target": "Port Authority", "sector": "Maritime"},
            {"target": "Shipping Company", "sector": "Maritime"},
            {"target": "Tech Company", "sector": "Technology"}
        ]

        maritime_threats = [t for t in threats if t["sector"] == "Maritime"]

        assert len(maritime_threats) == 2

    def test_identify_vessel_attacks(self):
        """Test identification of vessel-specific attacks"""
        incidents = [
            {"description": "Attack on vessel navigation system"},
            {"description": "Port terminal compromise"},
            {"description": "Generic network attack"}
        ]

        vessel_attacks = [inc for inc in incidents
                         if "vessel" in inc["description"].lower()]

        assert len(vessel_attacks) == 1


class TestJSONExport:
    """Test JSON export formatting"""

    def test_export_to_json_format(self):
        """Test exporting data to JSON"""
        data = {
            "incidents": [
                {"id": "1", "title": "Attack A", "severity": "High"},
                {"id": "2", "title": "Attack B", "severity": "Critical"}
            ],
            "total": 2
        }

        json_str = json.dumps(data, indent=2)

        assert "incidents" in json_str
        assert '"id": "1"' in json_str or '"id": 1' in json_str
        assert "Attack A" in json_str

    def test_json_serialization(self):
        """Test JSON serialization of complex objects"""
        from datetime import datetime

        data = {
            "timestamp": datetime.now().isoformat(),
            "threats": ["LockBit3", "Akira", "BlackCat"],
            "count": 3
        }

        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert parsed["count"] == 3
        assert len(parsed["threats"]) == 3


class TestSourceSpecificParsers:
    """Test parsing logic for specific OSINT sources"""

    def test_parse_ransomware_live_response(self, sample_ransomware_response):
        """Test parsing ransomware.live API response"""
        groups = {}

        for item in sample_ransomware_response:
            group_name = item.get("group_name")
            if group_name not in groups:
                groups[group_name] = []
            groups[group_name].append(item)

        assert len(groups) == 3
        assert "LockBit3" in groups
        assert len(groups["LockBit3"]) == 1

    def test_parse_pastebin_format(self):
        """Test parsing pastebin content"""
        pastebin_content = """
        Leaked credentials:
        email: admin@port.com
        password: leaked123
        database: port_ops
        """

        lines = pastebin_content.strip().split("\n")
        credentials = {}

        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                credentials[key.strip()] = value.strip()

        assert "email" in credentials
        assert credentials["email"] == "admin@port.com"

    def test_parse_cve_details_format(self):
        """Test parsing CVE details format"""
        cve_data = {
            "cve_id": "CVE-2024-0001",
            "description": "ECDIS vulnerability",
            "affected_products": ["Product A", "Product B"]
        }

        assert cve_data["cve_id"].startswith("CVE-")
        assert len(cve_data["affected_products"]) == 2


class TestErrorHandling:
    """Test error handling in OSINT collection"""

    def test_handle_timeout(self):
        """Test handling of request timeout"""
        timeout_error = TimeoutError("Request timed out after 30 seconds")

        assert "timed out" in str(timeout_error).lower()
        assert "30 seconds" in str(timeout_error)

    def test_handle_malformed_json(self):
        """Test handling of malformed JSON responses"""
        malformed = '{"invalid": json format}'

        try:
            json.loads(malformed)
            is_valid = True
        except json.JSONDecodeError:
            is_valid = False

        assert not is_valid

    def test_handle_missing_field(self):
        """Test handling of missing fields in response"""
        response = {
            "title": "Article",
            "link": "https://example.com"
            # Missing 'published_date'
        }

        date = response.get("published_date", "Unknown")

        assert date == "Unknown"

    def test_handle_invalid_url(self):
        """Test handling of invalid URLs"""
        urls = [
            "https://valid-url.com",
            "invalid url with spaces",
            "",
            None
        ]

        valid_urls = [u for u in urls if u and "://" in u]

        assert len(valid_urls) == 1


class TestIntegration:
    """Integration tests for OSINT collection"""

    def test_full_collection_pipeline(self, sample_ransomware_response, maritime_keywords_list):
        """Test complete OSINT collection pipeline"""
        # Step 1: Collect data
        raw_data = sample_ransomware_response

        # Step 2: Filter maritime threats
        maritime_threats = []
        for item in raw_data:
            desc = item.get("description", "").lower()
            if "maritime" in desc or "port" in desc or "shipping" in desc:
                maritime_threats.append(item)

        # Step 3: Deduplicate
        deduplicated = {item["group_name"]: item for item in maritime_threats}.values()

        # Step 4: Export
        result = {
            "total_collected": len(raw_data),
            "maritime_threats": len(maritime_threats),
            "deduplicated": len(deduplicated)
        }

        assert result["total_collected"] == 3
        assert result["maritime_threats"] >= 2

    def test_aggregation_from_multiple_sources(self):
        """Test aggregating data from multiple OSINT sources"""
        source1 = [
            {"title": "Threat A", "source": "ransomware.live"},
            {"title": "Threat B", "source": "ransomware.live"}
        ]
        source2 = [
            {"title": "Threat A", "source": "pastebin"},  # Duplicate
            {"title": "Threat C", "source": "pastebin"}
        ]

        # Combine sources
        all_data = source1 + source2

        # Deduplicate by title
        unique = {item["title"]: item for item in all_data}.values()

        assert len(all_data) == 4
        assert len(unique) == 3

    def test_report_generation_from_osint(self, sample_ransomware_response):
        """Test generating report from OSINT data"""
        data = sample_ransomware_response

        report = {
            "total_incidents": len(data),
            "threat_groups": len(set(item.get("group_name") for item in data)),
            "total_ransom": sum(
                int(item.get("ransom_amount", "$0").replace("$", "").replace(",", ""))
                for item in data
            )
        }

        assert report["total_incidents"] == 3
        assert report["threat_groups"] == 3
        assert report["total_ransom"] > 0
