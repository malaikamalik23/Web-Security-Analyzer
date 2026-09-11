import requests
from urllib.parse import urlparse
from html.parser import HTMLParser


class ExternalResourceParser(HTMLParser):
    """Extracts <script src=...> and <link rel=stylesheet href=...> tags,
    tracking whether each has an integrity attribute."""

    def __init__(self, page_hostname):
        super().__init__()
        self.page_hostname = page_hostname
        self.resources = []  # list of (url, tag_type, has_integrity)

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "script" and "src" in attrs_dict:
            self._check_resource(attrs_dict["src"], "script", "integrity" in attrs_dict)

        elif tag == "link" and attrs_dict.get("rel") == "stylesheet" and "href" in attrs_dict:
            self._check_resource(attrs_dict["href"], "stylesheet", "integrity" in attrs_dict)

    def _check_resource(self, resource_url, tag_type, has_integrity):
        parsed = urlparse(resource_url)
        # Only care about resources loaded from a DIFFERENT domain (external CDNs)
        if parsed.hostname and parsed.hostname != self.page_hostname:
            self.resources.append((resource_url, tag_type, has_integrity))


def check_sri(url):
    """Checks whether external scripts/stylesheets use Subresource Integrity."""
    findings = []

    try:
        r = requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        return findings  # connectivity issues already handled by check_headers

    page_hostname = urlparse(url).hostname
    parser = ExternalResourceParser(page_hostname)

    try:
        parser.feed(r.text)
    except Exception:
        return findings  # malformed HTML shouldn't crash the whole scan

    missing_sri = [res for res in parser.resources if not res[2]]

    if missing_sri:
        example_domains = sorted(set(urlparse(u).hostname for u, _, _ in missing_sri))[:3]
        findings.append({
            "header": "Missing Subresource Integrity",
            "status": f"{len(missing_sri)} external script/stylesheet tag(s) without an integrity attribute (e.g. from {', '.join(example_domains)})",
            "category": "Security Configuration",
        })

    return findings


if __name__ == "__main__":
    results = check_sri("https://example.com")
    for f in results:
        print(f)
    if not results:
        print("No SRI findings.")