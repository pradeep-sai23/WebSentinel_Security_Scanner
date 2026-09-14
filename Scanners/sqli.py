import requests


SQLI_TESTS = [
    "'",
    '"',
    "' OR '1'='1"
]

SQL_ERROR_MESSAGES = [
    "sql syntax",
    "mysql",
    "sqlite",
    "postgresql",
    "postgres",
    "oracle",
    "odbc",
    "database error",
    "syntax error",
]


def scan_sqli(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as error:
        return [{
            "type": "SQL Injection",
            "severity": "Info",
            "url": url,
            "evidence": f"Request failed: {error}"
        }]

    from bs4 import BeautifulSoup

    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()

        if method != "get":
            continue

        inputs = form.find_all("input")

        for field in inputs:
            name = field.get("name")

            if not name:
                continue

            for test in SQLI_TESTS:

                try:
                    test_response = requests.get(
                        action if action.startswith("http") else url.rstrip("/") + "/" + action.lstrip("/"),
                        params={name: test},
                        timeout=5
                    )

                    response_text = test_response.text.lower()

                    for error_message in SQL_ERROR_MESSAGES:

                        if error_message in response_text:
                            findings.append({
                                "type": "Possible SQL Injection",
                                "severity": "High",
                                "url": test_response.url,
                                "parameter": name,
                                "evidence": (
                                    f"Database-related error indicator "
                                    f"'{error_message}' detected after test input."
                                ),
                                "recommendation": (
                                    "Use parameterized queries/prepared statements "
                                    "and avoid constructing SQL queries through string concatenation."
                                )
                            })

                            break

                except requests.RequestException:
                    continue

    return findings
