import requests
from urllib.parse import urlparse


def check_endpoints(url):
    """Checks for robots.txt and security.txt, and flags anything notably exposed in them."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # robots.txt
    try:
        r = requests.get(f"{base}/robots.txt", timeout=5)
        if r.status_code == 200:
            # Not a vulnerability by itself — just useful info to report
            disallowed_count = r.text.lower().count("disallow:")
            findings.append({
                "header": "robots.txt",
                "status": f"present ({disallowed_count} Disallow rules)",
                "category": "Information Exposure",
            })
    except requests.exceptions.RequestException:
        pass  # absence or connection failure isn't itself a finding here

    # security.txt (per RFC 9116, may live at /security.txt or /.well-known/security.txt)
    security_txt_found = False
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = requests.get(f"{base}{path}", timeout=5)
            if r.status_code == 200 and "contact" in r.text.lower():
                security_txt_found = True
                break
        except requests.exceptions.RequestException:
            continue

    if not security_txt_found:
        findings.append({
            "header": "security.txt",
            "status": "missing",
            "category": "Information Exposure",
        })

    return findings


if __name__ == "__main__":
    results = check_endpoints("https://example.com")
    for f in results:
        print(f)
    if not results:
        print("No endpoint findings.")