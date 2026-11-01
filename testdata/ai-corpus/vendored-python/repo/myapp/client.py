import sys

sys.path.insert(0, "third_party")

import requests  # noqa: E402


def fetch(url):
    return requests.get(url, timeout=5)
