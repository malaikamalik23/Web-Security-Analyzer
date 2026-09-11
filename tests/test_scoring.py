from risk_engine.scorer import score_findings


def test_header_severity_exact_match():
    findings = [{"header": "Content-Security-Policy", "status": "missing", "category": "Security Configuration"}]
    result = score_findings(findings)
    assert result[0]["severity"] == "Medium"


def test_tls_certificate_high_severity():
    findings = [{"header": "TLS Certificate", "status": "expired", "category": "Transport"}]
    result = score_findings(findings)
    assert result[0]["severity"] == "High"


def test_cookie_secure_flag_partial_match():
    findings = [{"header": "Cookie 'session_id' Secure flag", "status": "missing", "category": "Session"}]
    result = score_findings(findings)
    assert result[0]["severity"] == "High"  # this is the exact bug we just caught


def test_cookie_httponly_flag_partial_match():
    findings = [{"header": "Cookie 'session_id' HttpOnly flag", "status": "missing", "category": "Session"}]
    result = score_findings(findings)
    assert result[0]["severity"] == "High"


def test_cookie_samesite_flag_partial_match():
    findings = [{"header": "Cookie 'session_id' SameSite flag", "status": "missing", "category": "Session"}]
    result = score_findings(findings)
    assert result[0]["severity"] == "Medium"


def test_unknown_header_defaults_to_low():
    findings = [{"header": "Some-Made-Up-Header", "status": "missing", "category": "Unknown"}]
    result = score_findings(findings)
    assert result[0]["severity"] == "Low"