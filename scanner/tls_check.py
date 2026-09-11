import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check_https_redirect(url):
    """Checks if HTTPS is enabled and whether HTTP redirects to it."""
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    try:
        https_url = f"https://{hostname}"
        requests.get(https_url, timeout=5)
        https_works = True
    except requests.exceptions.RequestException:
        https_works = False

    if not https_works:
        findings.append({
            "header": "HTTPS",
            "status": "not enabled",
            "category": "Transport",
        })
        return findings

    try:
        http_url = f"http://{hostname}"
        r = requests.get(http_url, timeout=5, allow_redirects=False)
        redirect_ok = r.status_code in (301, 302, 307, 308) and r.headers.get("Location", "").startswith("https://")
    except requests.exceptions.RequestException:
        redirect_ok = False

    if not redirect_ok:
        findings.append({
            "header": "HTTP-to-HTTPS Redirect",
            "status": "missing",
            "category": "Transport",
        })

    return findings


def check_certificate(hostname, port=443):
    """Connects via SSL and pulls certificate issuer/expiry info."""
    findings = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert["notAfter"]
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days

        issuer = dict(x[0] for x in cert["issuer"])
        issuer_name = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

        if days_remaining < 0:
            findings.append({
                "header": "TLS Certificate",
                "status": f"expired ({expiry_date.date()})",
                "category": "Transport",
            })
        elif days_remaining < 30:
            findings.append({
                "header": "TLS Certificate",
                "status": f"expiring soon ({days_remaining} days left)",
                "category": "Transport",
            })

        return findings, {"issuer": issuer_name, "expiry": str(expiry_date.date()), "days_remaining": days_remaining}

    except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        findings.append({
            "header": "TLS Certificate",
            "status": f"could not verify ({type(e).__name__})",
            "category": "Transport",
            "confidence": "Low",  # connection failure ≠ confirmed broken cert
        })
        return findings, None


if __name__ == "__main__":
    redirect_findings = check_https_redirect("https://example.com")
    cert_findings, cert_info = check_certificate("example.com")

    print("Redirect findings:", redirect_findings)
    print("Cert findings:", cert_findings)
    print("Cert info:", cert_info)