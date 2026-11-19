
import re
import math
import ipaddress
from collections import Counter
from urllib.parse import urlparse


FEATURES = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "special_char_count",
    "digits_count",
    "entropy"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update",
    "secure", "banking", "confirm", "password",
    "signin", "free", "wallet", "bonus"
]

SPECIAL_CHARS = set("-_@%&=./:?#")


def calculate_entropy(text):
    if not text:
        return 0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(url):

    original_url = str(url).strip()

    if not original_url:
        raise ValueError("URL cannot be empty")

    # Preserve the HTTPS signal before normalizing the URL.
    has_https = int(original_url.lower().startswith("https://"))

    # Remove the scheme only for the remaining URL-text features.
    raw_url = re.sub(
        r"^https?://",
        "",
        original_url,
        flags=re.IGNORECASE
    )

    # Parse normalized URL
    parsed = urlparse("http://" + raw_url)
    host = parsed.hostname or ""

    # Check IP address
    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0

    lower_url = raw_url.lower()

    suspicious_count = sum(
        word in lower_url for word in SUSPICIOUS_WORDS
    )

    query = parsed.query

    num_params = len(
        [item for item in query.split("&") if item]
    )

    features = {
        "url_length": len(raw_url),
        "num_dots": raw_url.count("."),
        "has_https": has_https,
        "has_ip": has_ip,
        "num_subdirs": raw_url.count("/"),
        "num_params": num_params,
        "suspicious_words": suspicious_count,
        "special_char_count": sum(
            char in SPECIAL_CHARS for char in raw_url
        ),
        "digits_count": sum(
            char.isdigit() for char in raw_url
        ),
        "entropy": calculate_entropy(raw_url)
    }

    return features
