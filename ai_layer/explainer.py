import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

USE_AI = True  # using Groq's free API

client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=os.environ.get("GROQ_API_KEY"),
)

TEMPLATES = {
    "Content-Security-Policy": {
        "meaning": "The application does not define a Content-Security-Policy, so the browser has no restriction on which sources scripts, styles, or other resources can load from.",
        "impact": "An attacker who manages to inject malicious script (e.g. via XSS) faces no additional browser-level barrier, making such attacks more likely to succeed.",
        "action": "Define a Content-Security-Policy header that restricts script and resource sources to trusted origins.",
    },
    "Strict-Transport-Security": {
        "meaning": "The application does not send an HSTS header, so browsers are not instructed to always use HTTPS for this site.",
        "impact": "Users could be downgraded to an insecure HTTP connection, for example via a man-in-the-middle attack on an unsecured network, exposing their traffic.",
        "action": "Add a Strict-Transport-Security header with an appropriate max-age to enforce HTTPS-only connections.",
    },
    "X-Frame-Options": {
        "meaning": "The application may be more exposed to clickjacking attacks, since no anti-framing header is present.",
        "impact": "An attacker may be able to embed the site inside another webpage and trick users into interacting with it unknowingly.",
        "action": "Configure an appropriate anti-framing policy, such as CSP frame-ancestors, or set X-Frame-Options explicitly.",
    },
    "X-Content-Type-Options": {
        "meaning": "The application does not send X-Content-Type-Options, so browsers may try to guess (\"sniff\") content types instead of trusting the declared one.",
        "impact": "This can allow certain files to be interpreted in unexpected ways, occasionally enabling attacks like disguised script execution.",
        "action": "Add the header X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    },
    "Referrer-Policy": {
        "meaning": "No Referrer-Policy is set, so the browser uses default behavior for what referrer information is sent to other sites.",
        "impact": "Sensitive URL parameters or internal paths could be leaked to third-party sites via the Referer header when users click outbound links.",
        "action": "Set a Referrer-Policy such as strict-origin-when-cross-origin to limit what referrer data is shared.",
    },
    "HTTPS": {
        "meaning": "The application does not appear to support HTTPS at all, meaning traffic between users and the server is unencrypted.",
        "impact": "Anyone able to observe network traffic — on public WiFi, a compromised router, or via other interception — can read or tamper with all data exchanged, including credentials and session tokens.",
        "action": "Obtain and configure a TLS certificate, then enforce HTTPS for all traffic.",
    },
    "TLS Certificate": {
        "meaning": "The application's TLS certificate is expired, expiring soon, or could not be verified.",
        "impact": "Browsers will warn or block users from connecting once the certificate is invalid, and in some cases traffic may become unencrypted or vulnerable to interception.",
        "action": "Renew the certificate before expiry and confirm it is properly installed and trusted.",
    },
    "HTTP-to-HTTPS Redirect": {
        "meaning": "The application does not redirect plain HTTP requests to HTTPS, so it's possible to reach the site over an unencrypted connection.",
        "impact": "Users who type the address without 'https://', or follow an old HTTP link, may have their traffic sent unencrypted, exposing it to interception even though HTTPS itself works fine.",
        "action": "Configure the server to redirect all HTTP requests to HTTPS (typically a 301 redirect).",
    },
    "Secure flag": {
        "meaning": "One or more cookies are set without the Secure flag, so they can be sent over unencrypted HTTP connections.",
        "impact": "If a user is ever on an unencrypted connection, the cookie could be intercepted, potentially allowing session hijacking.",
        "action": "Set the Secure flag on all cookies so they are only ever sent over HTTPS.",
    },
    "HttpOnly flag": {
        "meaning": "One or more cookies are set without the HttpOnly flag, so they are accessible to JavaScript running on the page.",
        "impact": "If an attacker manages to inject malicious script (XSS), they could read and steal this cookie directly.",
        "action": "Set the HttpOnly flag on session and sensitive cookies to prevent client-side script access.",
    },
    "SameSite flag": {
        "meaning": "One or more cookies are set without a SameSite attribute, so browser defaults govern cross-site request behavior.",
        "impact": "This can leave the application more exposed to cross-site request forgery (CSRF) attacks under certain conditions.",
        "action": "Set SameSite=Lax or SameSite=Strict on cookies, depending on the application's cross-site needs.",
    },
    "security.txt": {
        "meaning": "No security.txt file was found, so there's no standardized way for security researchers to know how to report a vulnerability if they find one.",
        "impact": "Legitimate vulnerability reports may be delayed, sent to the wrong place, or never reach the right team, since there's no published contact process.",
        "action": "Publish a security.txt file at /.well-known/security.txt per RFC 9116, including a contact method.",
    },
        "CORS Wildcard Origin": {
        "meaning": "The server responds to cross-origin requests with Access-Control-Allow-Origin: *, permitting any website to read its responses.",
        "impact": "If the endpoint returns sensitive data, any malicious site could fetch it directly from a visitor's browser, since the browser trusts the server's explicit permission.",
        "action": "Restrict Access-Control-Allow-Origin to a specific, trusted list of origins instead of using a wildcard, especially for endpoints returning sensitive data.",
    },
    "CORS Wildcard with Credentials": {
        "meaning": "The server sends both a wildcard Access-Control-Allow-Origin and Access-Control-Allow-Credentials: true, an invalid and dangerous combination.",
        "impact": "While most browsers reject this exact combination, it signals a fundamentally broken CORS configuration that likely has other, exploitable issues.",
        "action": "Never combine a wildcard origin with credentialed requests; specify exact trusted origins whenever credentials are involved.",
    },
    "CORS Reflects Arbitrary Origin": {
        "meaning": "The server reflects whatever Origin header a client sends back in Access-Control-Allow-Origin, rather than validating it against an allowlist.",
        "impact": "This effectively grants every website on the internet the same cross-origin access a wildcard would, often paired with credentials, making it worse than a plain wildcard in practice.",
        "action": "Validate the Origin header against a strict allowlist of trusted domains before reflecting it, rather than accepting any value.",
    },
    "Exposed": {
        "meaning": "A sensitive file that should not be publicly accessible was found to be reachable directly via the web server.",
        "impact": "Depending on the file, this can expose source code, credentials, database contents, or internal configuration details to anyone who requests the URL directly.",
        "action": "Remove or restrict access to this file immediately — configure the web server to block access to sensitive paths, and rotate any credentials that may have been exposed.",
    },
}

DEFAULT_TEMPLATE = {
    "meaning": "This finding indicates a deviation from a recommended security configuration.",
    "impact": "This could increase the application's exposure to certain classes of attack.",
    "action": "Review the relevant security configuration and apply the recommended setting.",
}


def _get_template(header):
    template = TEMPLATES.get(header)
    if template is None:
        for key, tpl in TEMPLATES.items():
            if key in header:
                template = tpl
                break
    return template or DEFAULT_TEMPLATE


def explain_finding(finding):
    confidence_note = ""
    if finding.get("confidence") == "Low":
        confidence_note = " (Note: this could not be fully verified — it may reflect a network issue rather than a confirmed problem.)"

    if USE_AI:
        prompt = f"""You are a security analysis assistant. A web scanner detected the following finding:

Header: {finding['header']}
Status: {finding['status']}{confidence_note}
Severity: {finding['severity']}
Category: {finding['category']}
...

Respond with exactly these four sections, each 1-2 sentences, no extra commentary:

What does this mean?
Why does it matter?
Recommended action:
Category: (restate the OWASP/security category)
"""
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}],
        )
        return f"Risk: {finding['severity']}\n\n{response.choices[0].message.content}"

    template = _get_template(finding["header"])
    return f"""Risk: {finding['severity']}

What does this mean?
{template['meaning']}

Why does it matter?
{template['impact']}

Recommended action:
{template['action']}

Category: {finding['category']}"""


if __name__ == "__main__":
    test_finding = {
        "header": "X-Frame-Options",
        "status": "missing",
        "category": "Session/Clickjacking",
        "severity": "Medium",
    }

    print(explain_finding(test_finding))