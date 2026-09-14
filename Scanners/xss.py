import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


def scan_xss(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as error:
        return [{
            "type": "XSS",
            "severity": "Info",
            "url": url,
            "evidence": f"Request failed: {error}"
        }]

    # Find forms on the page
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()

        if method != "get":
            continue

        target = urljoin(url, action)
        inputs = form.find_all("input")

        for field in inputs:
            name = field.get("name")

            if not name:
                continue

            marker = "WebSentinelXSS123"

            params = {
                name: marker
            }

            try:
                test_response = requests.get(
                    target,
                    params=params,
                    timeout=5
                )

                if marker in test_response.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "High",
                        "url": test_response.url,
                        "parameter": name,
                        "evidence": f"Test marker '{marker}' was reflected in the response",
                        "recommendation": (
                            "Properly encode user-controlled output and "
                            "apply appropriate input validation and CSP."
                        )
                    })

            except requests.RequestException:
                continue

    return findings
