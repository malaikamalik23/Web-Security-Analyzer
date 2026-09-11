import requests
from urllib.parse import urlparse

# Paths that should never be publicly accessible if present
SENSITIVE_PATHS = [
    (".git/config", "Exposed .git repository", "High"),
    (".env", "Exposed .env file", "High"),
    ("wp-config.php.bak", "Exposed backup config file", "High"),
    ("config.php.bak", "Exposed backup config file", "High"),
    (".DS_Store", "Exposed macOS metadata file", "Low"),
    ("backup.zip", "Exposed backup archive", "Medium"),
    ("database.sql", "Exposed database dump", "High"),
]


def check_exposed_files(url):
    """Checks for common accidentally-exposed sensitive files."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path, description, severity in SENSITIVE_PATHS:
        try:
            r = requests.get(f"{base}/{path}", timeout=5)

            # Reject soft-404s: many sites return 200 with a normal HTML page
            # instead of a real 404 for unknown paths. A genuinely exposed
            # sensitive file should NOT look like an HTML page.
            looks_like_html = "<html" in r.text[:500].lower() or "<!doctype" in r.text[:500].lower()

            if r.status_code == 200 and len(r.content) > 20 and not looks_like_html:
                findings.append({
                    "header": description,
                    "status": f"Publicly accessible at /{path}",
                    "category": "Information Exposure",
                    "_severity_override": severity,
                })
        except requests.exceptions.RequestException:
            continue

    return findings


if __name__ == "__main__":
    results = check_exposed_files("https://example.com")
    for f in results:
        print(f)
    if not results:
        print("No exposed file findings.")