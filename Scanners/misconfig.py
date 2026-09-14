import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS and content injection.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Helps prevent clickjacking.",
    "Referrer-Policy": "Controls referrer information leakage."
}


def scan_misconfiguration(url):
    findings = []

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )
    except requests.RequestException as error:
        return [{
            "type": "Security Misconfiguration",
            "severity": "Info",
            "url": url,
            "evidence": f"Request failed: {error}"
        }]

    # -----------------------------------
    # 1. Security headers
    # -----------------------------------

    for header, description in SECURITY_HEADERS.items():

        if header not in response.headers:

            findings.append({
                "type": "Missing Security Header",
                "severity": "Medium",
                "url": url,
                "evidence": f"{header} header is missing.",
                "recommendation": description
            })

    # -----------------------------------
    # 2. Server information disclosure
    # -----------------------------------

    server = response.headers.get("Server")

    if server:

        findings.append({
            "type": "Information Disclosure",
            "severity": "Low",
            "url": url,
            "evidence": f"Server header reveals: {server}",
            "recommendation": (
                "Avoid exposing unnecessary server software "
                "and version information."
            )
        })

    # -----------------------------------
    # 3. CORS configuration
    # -----------------------------------

    cors = response.headers.get("Access-Control-Allow-Origin")

    if cors == "*":

        findings.append({
            "type": "Permissive CORS",
            "severity": "Medium",
            "url": url,
            "evidence": (
                "Access-Control-Allow-Origin is set to '*'."
            ),
            "recommendation": (
                "Restrict CORS to trusted origins instead of "
                "allowing every origin."
            )
        })

    # -----------------------------------
    # 4. HTTPS check
    # -----------------------------------

    if url.startswith("http://"):

        findings.append({
            "type": "Unencrypted HTTP",
            "severity": "Medium",
            "url": url,
            "evidence": "Target is being accessed over HTTP.",
            "recommendation": (
                "Use HTTPS to protect data transmitted "
                "between clients and the server."
            )
        })

    # -----------------------------------
    # 5. Cookie security
    # -----------------------------------

    cookies = response.cookies

    for cookie in cookies:

        if not cookie.secure:

            findings.append({
                "type": "Insecure Cookie",
                "severity": "Medium",
                "url": url,
                "evidence": (
                    f"Cookie '{cookie.name}' does not have "
                    "the Secure attribute."
                ),
                "recommendation": (
                    "Set the Secure attribute on sensitive "
                    "cookies and use HTTPS."
                )
            })

    return findings
