import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def scan_directory_listing(url):
    findings = []

    # Common paths that may expose directory listings
    paths = [
        "/uploads/",
        "/backup/",
        "/backups/",
        "/files/",
        "/documents/",
        "/downloads/",
	"/robots.txt",
	"/admin"
    ]

    for path in paths:
        target = urljoin(url, path)

        try:
            response = requests.get(
                target,
                timeout=5,
                allow_redirects=True
            )

            if response.status_code != 200:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            page_text = soup.get_text(" ", strip=True).lower()

            # Indicators of directory listing
            indicators = [
                "index of",
                "directory listing",
                "parent directory"
            ]

            if any(indicator in page_text for indicator in indicators):

                findings.append({
                    "type": "Directory Listing",
                    "severity": "Medium",
                    "url": target,
                    "evidence": (
                        f"Directory listing appears to be enabled at {target}"
                    ),
                    "recommendation": (
                        "Disable directory indexing and ensure sensitive "
                        "files are not publicly accessible."
                    )
                })

        except requests.RequestException:
            continue

    return findings
