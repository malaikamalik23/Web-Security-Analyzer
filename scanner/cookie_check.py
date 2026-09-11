import requests


def check_cookies(url):
    """Checks Secure, HttpOnly, and SameSite flags on any cookies the site sets,
    including cookies set on intermediate redirect responses."""
    findings = []

    try:
        r = requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        findings.append({
            "header": "Cookies",
            "status": "could not connect to check cookies",
            "category": "Session",
        })
        return findings

    # Gather cookies from the final response AND any redirects along the way
    all_cookies = list(r.cookies)
    for resp in r.history:
        all_cookies += list(resp.cookies)

    if not all_cookies:
        return findings

    seen = set()
    for cookie in all_cookies:
        if cookie.name in seen:
            continue  # avoid duplicate findings if the same cookie appears twice
        seen.add(cookie.name)

        if not cookie.secure:
            findings.append({
                "header": f"Cookie '{cookie.name}' Secure flag",
                "status": "missing",
                "category": "Session",
            })

        has_httponly = "httponly" in [k.lower() for k in cookie._rest.keys()]
        if not has_httponly:
            findings.append({
                "header": f"Cookie '{cookie.name}' HttpOnly flag",
                "status": "missing",
                "category": "Session",
            })

        samesite = cookie._rest.get("SameSite") or cookie._rest.get("samesite")
        if not samesite:
            findings.append({
                "header": f"Cookie '{cookie.name}' SameSite flag",
                "status": "missing",
                "category": "Session",
            })

    return findings


if __name__ == "__main__":
    results = check_cookies("https://httpbin.org/cookies/set/testcookie/12345")
    for f in results:
        print(f)
    if not results:
        print("No cookie findings.")