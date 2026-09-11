import pytest
import requests
from scanner.header_check import check_headers
from scanner.cookie_check import check_cookies
from scanner.endpoint_check import check_endpoints
from scanner.tls_check import check_certificate
from scanner.cors_check import check_cors
from scanner.sri_check import check_sri
from scanner.exposed_files_check import check_exposed_files

BASE_URL = "http://127.0.0.1:5001"
TLS_BASE_URL = "127.0.0.1"
TLS_PORT = 5002


def _server_is_running():
    try:
        requests.get(f"{BASE_URL}/good", timeout=2)
        return True
    except requests.exceptions.RequestException:
        return False


requires_test_server = pytest.mark.skipif(
    not _server_is_running(),
    reason="test-target Flask server is not running on port 5001 — start it with 'python app.py' in the test-target project first",
)


@requires_test_server
def test_headers_bad_route_flags_all_five():
    findings = check_headers(f"{BASE_URL}/bad")
    headers_found = {f["header"] for f in findings}
    expected = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    }
    assert headers_found == expected


@requires_test_server
def test_headers_good_route_flags_nothing():
    findings = check_headers(f"{BASE_URL}/good")
    assert findings == []


@requires_test_server
def test_cookies_bad_route_flags_all_three():
    findings = check_cookies(f"{BASE_URL}/bad")
    assert len(findings) == 3
    flag_types = {f["header"].split()[-2] for f in findings}  # Secure, HttpOnly, SameSite
    assert flag_types == {"Secure", "HttpOnly", "SameSite"}


@requires_test_server
def test_cookies_good_route_flags_nothing():
    findings = check_cookies(f"{BASE_URL}/good")
    assert findings == []

@requires_test_server
def test_endpoints_present_when_configured():
    findings = check_endpoints(BASE_URL)
    finding_headers = {f["header"] for f in findings}
    # security.txt should NOT appear as "missing" since we now serve it
    assert "security.txt" not in finding_headers


@requires_test_server
def test_endpoints_robots_txt_detected_when_present():
    findings = check_endpoints(BASE_URL)
    robots_finding = next((f for f in findings if f["header"] == "robots.txt"), None)
    assert robots_finding is not None
    assert "2" in robots_finding["status"]  # 2 Disallow rules

@requires_test_server
def test_tls_self_signed_cert_flagged_with_low_confidence():
    findings, info = check_certificate(TLS_BASE_URL, port=TLS_PORT)
    assert len(findings) == 1
    assert findings[0]["header"] == "TLS Certificate"
    assert findings[0]["confidence"] == "Low"
    assert info is None

@requires_test_server
def test_cors_bad_route_flags_reflected_origin():
    findings = check_cors(f"{BASE_URL}/cors-bad")
    assert len(findings) == 1
    assert findings[0]["header"] == "CORS Reflects Arbitrary Origin"


@requires_test_server
def test_cors_good_route_flags_nothing():
    findings = check_cors(f"{BASE_URL}/cors-good")
    assert findings == []

from scanner.sri_check import check_sri


@requires_test_server
def test_sri_bad_route_flags_missing_integrity():
    findings = check_sri(f"{BASE_URL}/sri-bad")
    assert len(findings) == 1
    assert findings[0]["header"] == "Missing Subresource Integrity"


@requires_test_server
def test_sri_good_route_flags_nothing():
    findings = check_sri(f"{BASE_URL}/sri-good")
    assert findings == []

@requires_test_server
def test_exposed_files_detects_git_config_and_env():
    findings = check_exposed_files(BASE_URL)
    headers_found = {f["header"] for f in findings}
    assert "Exposed .git repository" in headers_found
    assert "Exposed .env file" in headers_found


@requires_test_server
def test_exposed_files_no_false_positives_for_undefined_paths():
    findings = check_exposed_files(BASE_URL)
    # Should only find the 2 we deliberately exposed, not the other 5 checked paths
    assert len(findings) == 2