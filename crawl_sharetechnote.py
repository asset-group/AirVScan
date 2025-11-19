from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

start_url = "https://www.sharetechnote.com/html/5G/Handbook_5G_Index.html"

res = requests.get(start_url)
soup = BeautifulSoup(res.text, "lxml")

for li in soup.find_all("li"):
    a_tag = li.find("a")
    if a_tag is not None and a_tag.get("href") and a_tag:
        href = a_tag["href"]
        if href.startswith("../"):
            continue

        # crawl each page
        url = urljoin(start_url, href)
        res = requests.get(url)
        with open(f"documents/fiveg/sharetechnotes/{href}", "w", encoding="utf8") as f:
            f.write(res.text)
