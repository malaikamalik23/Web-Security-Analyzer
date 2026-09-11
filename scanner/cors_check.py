import requests


def check_cors(url):
    """Checks for overly permissive CORS configuration."""
    findings = []

    try:
        # Send a request with an Origin header, simulating a cross-site request
        headers = {"Origin": "https://evil-example-attacker.com"}
        r = requests.get(url, headers=headers, timeout=5)
    except requests.exceptions.RequestException:
        return findings  # connectivity issues are already handled by check_headers

    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")

    if acao == "*":
        if acac and acac.lower() == "true":
            # This combination is actually invalid per spec and browsers reject it,
            # but a server sending it anyway indicates a real misconfiguration
            findings.append({
                "header": "CORS Wildcard with Credentials",
                "status": "Access-Control-Allow-Origin: * combined with Allow-Credentials: true",
                "category": "Security Configuration",
            })
        else:
            findings.append({
                "header": "CORS Wildcard Origin",
                "status": "Access-Control-Allow-Origin: * (any site can read responses)",
                "category": "Security Configuration",
            })
    elif acao == "https://evil-example-attacker.com":
        # The server reflected our arbitrary Origin back — a common, dangerous misconfiguration
        findings.append({
            "header": "CORS Reflects Arbitrary Origin",
            "status": "Server reflected an untrusted Origin back in Access-Control-Allow-Origin",
            "category": "Security Configuration",
        })

    return findings


if __name__ == "__main__":
    results = check_cors("https://example.com")
    for f in results:
        print(f)
    if not results:
        print("No CORS findings.")