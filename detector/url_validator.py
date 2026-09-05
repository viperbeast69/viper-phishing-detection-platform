from urllib.parse import urlparse
import ipaddress
import re


MAX_URL_LENGTH = 2048


def validate_url(url):
    """
    Validate a URL before sending it through the phishing
    detection pipeline.

    Returns:
        {
            "valid": bool,
            "normalized_url": str,
            "error": str or None,
            "hostname": str or None
        }
    """

    if url is None:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "URL is required.",
            "hostname": None
        }

    if not isinstance(url, str):
        return {
            "valid": False,
            "normalized_url": None,
            "error": "URL must be a text string.",
            "hostname": None
        }

    url = url.strip()

    # ------------------------------------------------------------
    # Empty URL
    # ------------------------------------------------------------

    if not url:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "URL cannot be empty.",
            "hostname": None
        }

    # ------------------------------------------------------------
    # Maximum length
    # ------------------------------------------------------------

    if len(url) > MAX_URL_LENGTH:
        return {
            "valid": False,
            "normalized_url": None,
            "error": f"URL exceeds the maximum allowed length of {MAX_URL_LENGTH} characters.",
            "hostname": None
        }

    # ------------------------------------------------------------
    # Reject whitespace
    # ------------------------------------------------------------

    if re.search(r"\s", url):
        return {
            "valid": False,
            "normalized_url": None,
            "error": "URL cannot contain spaces or whitespace characters.",
            "hostname": None
        }

    # ------------------------------------------------------------
    # Add HTTPS when scheme is omitted
    #
    # Example:
    # google.com
    # becomes:
    # https://google.com
    # ------------------------------------------------------------

    normalized_url = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized_url):
        normalized_url = "https://" + normalized_url

    # ------------------------------------------------------------
    # Parse URL
    # ------------------------------------------------------------

    try:
        parsed = urlparse(normalized_url)
    except Exception:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Unable to parse the URL.",
            "hostname": None
        }

    # ------------------------------------------------------------
    # Only HTTP and HTTPS are supported
    # ------------------------------------------------------------

    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Only HTTP and HTTPS URLs are supported.",
            "hostname": None
        }

    # ------------------------------------------------------------
    # Hostname must exist
    # ------------------------------------------------------------

    try:
        hostname = parsed.hostname
    except ValueError:
        hostname = None

    if not hostname:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "URL does not contain a valid hostname.",
            "hostname": None
        }

    hostname = hostname.lower().rstrip(".")

    # ------------------------------------------------------------
    # Reject malformed hostname characters
    # ------------------------------------------------------------

    if any(ord(character) < 32 for character in hostname):
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Hostname contains invalid control characters.",
            "hostname": hostname
        }

    # ------------------------------------------------------------
    # Validate port if present
    # ------------------------------------------------------------

    try:
        port = parsed.port

        if port is not None and not (1 <= port <= 65535):
            return {
                "valid": False,
                "normalized_url": None,
                "error": "Port number must be between 1 and 65535.",
                "hostname": hostname
            }

    except ValueError:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Invalid port number.",
            "hostname": hostname
        }

    # ------------------------------------------------------------
    # IP address validation
    #
    # Both IPv4 and IPv6 are allowed.
    # ------------------------------------------------------------

    try:
        ipaddress.ip_address(hostname)

        return {
            "valid": True,
            "normalized_url": normalized_url,
            "error": None,
            "hostname": hostname
        }

    except ValueError:
        pass

    # ------------------------------------------------------------
    # Domain hostname validation
    # ------------------------------------------------------------

    # Hostnames cannot begin or end with a hyphen.
    if hostname.startswith("-") or hostname.endswith("-"):
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Hostname cannot begin or end with a hyphen.",
            "hostname": hostname
        }

    # Reject consecutive dots.
    if ".." in hostname:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Hostname contains consecutive dots.",
            "hostname": hostname
        }

    # Split hostname into labels.
    labels = hostname.split(".")

    for label in labels:

        if not label:
            return {
                "valid": False,
                "normalized_url": None,
                "error": "Hostname contains an empty domain label.",
                "hostname": hostname
            }

        if len(label) > 63:
            return {
                "valid": False,
                "normalized_url": None,
                "error": "A hostname label exceeds 63 characters.",
                "hostname": hostname
            }

        if label.startswith("-") or label.endswith("-"):
            return {
                "valid": False,
                "normalized_url": None,
                "error": "Domain labels cannot begin or end with a hyphen.",
                "hostname": hostname
            }

        # Allow normal DNS characters plus Unicode domain names.
        if not re.match(r"^[a-zA-Z0-9\u0080-\uffff-]+$", label):
            return {
                "valid": False,
                "normalized_url": None,
                "error": "Hostname contains invalid characters.",
                "hostname": hostname
            }

    # ------------------------------------------------------------
    # Require a plausible domain structure.
    #
    # A hostname such as:
    # not-a-valid-url
    #
    # is rejected because it does not contain a domain suffix.
    #
    # IP addresses were already handled above.
    # ------------------------------------------------------------

    if len(labels) < 2:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Hostname must contain a valid domain structure.",
            "hostname": hostname
        }

    # ------------------------------------------------------------
    # TLD-like final label
    # ------------------------------------------------------------

    tld = labels[-1]

    if len(tld) < 2:
        return {
            "valid": False,
            "normalized_url": None,
            "error": "Domain suffix appears invalid.",
            "hostname": hostname
        }

    return {
        "valid": True,
        "normalized_url": normalized_url,
        "error": None,
        "hostname": hostname
    }