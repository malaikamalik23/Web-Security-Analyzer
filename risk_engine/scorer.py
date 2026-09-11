SEVERITY_MAP = {
    "Content-Security-Policy": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Frame-Options": "Medium",
    "X-Content-Type-Options": "Low",
    "Referrer-Policy": "Low",
    "HTTPS": "High",
    "HTTP-to-HTTPS Redirect": "Medium",
    "TLS Certificate": "High",
    "Secure flag": "High",
    "HttpOnly flag": "High",
    "SameSite flag": "Medium",
    "security.txt": "Low",
    "CORS Wildcard Origin": "Medium",
    "CORS Wildcard with Credentials": "High",
    "CORS Reflects Arbitrary Origin": "High",
    "Missing Subresource Integrity": "Medium",
}

CONFIDENCE_MAP = {
    "Content-Security-Policy": "High",       # deterministic header check
    "Strict-Transport-Security": "High",
    "X-Frame-Options": "High",
    "X-Content-Type-Options": "High",
    "Referrer-Policy": "High",
    "HTTPS": "Medium",                        # could reflect a network issue, not just the site
    "HTTP-to-HTTPS Redirect": "Medium",       # some sites redirect via non-standard means we might miss
    "TLS Certificate": "Medium",              # "could not verify" can mean expired OR unreachable
    "Secure flag": "High",
    "HttpOnly flag": "High",
    "SameSite flag": "High",
    "security.txt": "High",
    "Connectivity": "High",       
    "robots.txt": "High",      
    "CORS Wildcard Origin": "Medium",
    "CORS Wildcard with Credentials": "High",
    "CORS Reflects Arbitrary Origin": "High", 
    "Missing Subresource Integrity": "Medium",  
    "Exposed": "High",  # will substring-match all the exposed-file finding headers   # we're confident the site was unreachable
}

DEFAULT_CONFIDENCE = "Medium"


def score_findings(findings):
    scored = []
    for finding in findings:
        header = finding["header"]

        if "_severity_override" in finding:
            severity = finding["_severity_override"]
        else:
            severity = SEVERITY_MAP.get(header)
            if severity is None:
                for key, sev in SEVERITY_MAP.items():
                    if key in header:
                        severity = sev
                        break
            if severity is None:
                severity = "Low"

        confidence = CONFIDENCE_MAP.get(header)
        if confidence is None:
            for key, conf in CONFIDENCE_MAP.items():
                if key in header:
                    confidence = conf
                    break
        if confidence is None:
            confidence = DEFAULT_CONFIDENCE

        clean_finding = {k: v for k, v in finding.items() if k != "_severity_override"}
        scored.append({**clean_finding, "severity": severity, "confidence": confidence})
    return scored