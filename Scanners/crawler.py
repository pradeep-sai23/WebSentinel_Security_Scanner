import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl(start_url, max_pages=20):

    visited = set()
    queue = [start_url]
    discovered = []

    start_host = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:

        current_url = queue.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        try:
            response = requests.get(
                current_url,
                timeout=5,
                allow_redirects=True
            )
        except requests.RequestException:
            continue

        final_url = response.url

        if final_url not in discovered:
            discovered.append(final_url)

        content_type = response.headers.get(
            "Content-Type",
            ""
        )

        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # Discover normal links
        for link in soup.find_all("a", href=True):

            next_url = urljoin(
                current_url,
                link["href"]
            )

            parsed = urlparse(next_url)

            if parsed.netloc != start_host:
                continue

            clean_url = parsed._replace(
                fragment=""
            ).geturl()

            if clean_url not in visited:
                queue.append(clean_url)

        # Discover GET form actions
        for form in soup.find_all("form"):

            method = form.get(
                "method",
                "get"
            ).lower()

            if method != "get":
                continue

            action = form.get(
                "action",
                ""
            )

            if not action:
                action = current_url

            form_url = urljoin(
                current_url,
                action
            )

            parsed = urlparse(form_url)

            if parsed.netloc != start_host:
                continue

            clean_url = parsed._replace(
                fragment=""
            ).geturl()

            if clean_url not in visited:
                queue.append(clean_url)

    return discovered
