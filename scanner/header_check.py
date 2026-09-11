import requests

def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        return [{
            "header": "Connectivity",
            "status": "could not connect to target",
            "category": "General",
        }]

    headers = r.headers

    security_headers = {
        "Content-Security-Policy": "Security Configuration",
        "Strict-Transport-Security": "Transport",
        "X-Frame-Options": "Session/Clickjacking",
        "X-Content-Type-Options": "Security Configuration",
        "Referrer-Policy": "Information Exposure",
    }

    findings = []
    for header, category in security_headers.items():
        if header not in headers:
            findings.append({
                "header": header,
                "status": "missing",
                "category": category,
            })

    return findings

if __name__ == "__main__":
    results = check_headers("https://example.com")
    for f in results:
        print(f)