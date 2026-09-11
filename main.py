from scanner.header_check import check_headers
from scanner.tls_check import check_https_redirect, check_certificate
from scanner.cookie_check import check_cookies
from scanner.endpoint_check import check_endpoints
from risk_engine.scorer import score_findings
from ai_layer.explainer import explain_finding
from urllib.parse import urlparse
import requests
from scanner.cors_check import check_cors
from scanner.sri_check import check_sri
from scanner.exposed_files_check import check_exposed_files

def run_scan(url):
    hostname = urlparse(url).hostname

    try:
        requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        return [{
            "header": "Connectivity",
            "status": "Target unreachable — could not connect within 5 seconds",
            "category": "General",
            "severity": "Info",
            "explanation": "The scan could not complete because the target site did not respond. This could mean the site is down, blocking automated requests, or the URL is incorrect.",
        }]

    findings = check_headers(url)
    findings = check_headers(url)
    findings += check_https_redirect(url)
    findings += check_cors(url)
    findings += check_sri(url)
    findings += check_exposed_files(url)

    cert_findings, _ = check_certificate(hostname)
    findings += cert_findings

    findings += check_cookies(url)
    findings += check_endpoints(url)

    scored = score_findings(findings)
    for finding in scored:
        finding["explanation"] = explain_finding(finding)

    return scored

if __name__ == "__main__":
    url = "https://example.com"
    results = run_scan(url)

    for r in results:
        print("=" * 60)
        print(f"Header: {r['header']} | Severity: {r['severity']} | Category: {r['category']}")
        print("-" * 60)
        print(r["explanation"])
        print()