import sys
import requests

from Scanners.xss import scan_xss
from Scanners.sqli import scan_sqli
from Scanners.directory import scan_directory_listing
from Scanners.misconfig import scan_misconfiguration
from Scanners.crawler import crawl

from reports import save_report
from html_report import generate_html_report


def calculate_risk(findings):

    critical = 0
    high = 0
    medium = 0
    low = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            ""
        ).lower()

        if severity == "critical":
            critical += 1

        elif severity == "high":
            high += 1

        elif severity == "medium":
            medium += 1

        elif severity == "low":
            low += 1

    if critical > 0:
        risk = "CRITICAL"

    elif high > 0:
        risk = "HIGH"

    elif medium > 0:
        risk = "MEDIUM"

    elif low > 0:
        risk = "LOW"

    else:
        risk = "NONE"

    return critical, high, medium, low, risk


def check_target(url):

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        print("=" * 60)
        print("             WebSentinel Security Scanner")
        print("=" * 60)

        print(f"Target       : {url}")
        print(f"Final URL    : {response.url}")
        print(f"Status Code  : {response.status_code}")

        if response.url.startswith("https://"):
            print("HTTPS        : Yes")
        else:
            print("HTTPS        : No")

        print(
            f"Response Size: "
            f"{len(response.content)} bytes"
        )

        # --------------------------------------------------
        # URL CRAWLING
        # --------------------------------------------------

        print("\n" + "-" * 60)
        print("URL CRAWLING")
        print("-" * 60)

        urls = crawl(
            url,
            max_pages=20
        )

        print("\nDiscovered URLs:")

        for discovered_url in urls:
            print(f"  [+] {discovered_url}")

        print(
            f"\n[+] Total URLs discovered: "
            f"{len(urls)}"
        )

        # --------------------------------------------------
        # VULNERABILITY SCANNING
        # --------------------------------------------------

        print("\n" + "-" * 60)
        print("VULNERABILITY SCAN")
        print("-" * 60)

        findings = []

        for discovered_url in urls:

            print(
                f"\n[*] Scanning: "
                f"{discovered_url}"
            )

            try:

                xss_findings = scan_xss(
                    discovered_url
                )

                sqli_findings = scan_sqli(
                    discovered_url
                )

                directory_findings = scan_directory_listing(
                    discovered_url
                )

                misconfiguration_findings = scan_misconfiguration(
                    discovered_url
                )

                findings.extend(
                    xss_findings
                )

                findings.extend(
                    sqli_findings
                )

                findings.extend(
                    directory_findings
                )

                findings.extend(
                    misconfiguration_findings
                )

            except Exception as error:

                print(
                    f"[!] Scanner error on "
                    f"{discovered_url}: {error}"
                )

        # --------------------------------------------------
        # DISPLAY FINDINGS
        # --------------------------------------------------

        if findings:

            print("\n" + "-" * 60)
            print("FINDINGS")
            print("-" * 60)

            for finding in findings:

                print()

                print(
                    f"[{finding.get('severity', 'Unknown')}] "
                    f"{finding.get('type', 'Unknown')}"
                )

                print(
                    f"URL       : "
                    f"{finding.get('url', url)}"
                )

                print(
                    f"Parameter : "
                    f"{finding.get('parameter', 'N/A')}"
                )

                print(
                    f"Evidence  : "
                    f"{finding.get('evidence', 'N/A')}"
                )

                print(
                    f"Fix       : "
                    f"{finding.get('recommendation', 'N/A')}"
                )

        else:

            print(
                "\n[+] No potential vulnerabilities detected."
            )

        # --------------------------------------------------
        # RISK CALCULATION
        # --------------------------------------------------

        (
            critical,
            high,
            medium,
            low,
            risk
        ) = calculate_risk(findings)

        print("\n" + "=" * 60)
        print("                    SCAN SUMMARY")
        print("=" * 60)

        print(
            f"URLs Scanned   : {len(urls)}"
        )

        print(
            f"Total Findings : {len(findings)}"
        )

        print(
            f"Critical       : {critical}"
        )

        print(
            f"High           : {high}"
        )

        print(
            f"Medium         : {medium}"
        )

        print(
            f"Low            : {low}"
        )

        print(
            f"\nOverall Risk   : {risk}"
        )

        # --------------------------------------------------
        # SAVE REPORTS
        # --------------------------------------------------

        json_report = save_report(
            url,
            findings,
            critical,
            high,
            medium,
            low,
            risk
        )

        html_report = generate_html_report(
            url,
            findings,
            critical,
            high,
            medium,
            low,
            risk
        )

        print(
            f"\n[+] JSON report : "
            f"{json_report}"
        )

        print(
            f"[+] HTML report : "
            f"{html_report}"
        )

        print("=" * 60)

    except requests.exceptions.RequestException as error:

        print(
            f"[!] Connection error: "
            f"{error}"
        )


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python3 scanner.py <URL>"
        )

        sys.exit(1)

    target = sys.argv[1]

    if not target.startswith(
        ("http://", "https://")
    ):

        target = "http://" + target

    check_target(target)
