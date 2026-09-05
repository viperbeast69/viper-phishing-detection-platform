import tldextract
from urllib.parse import urlparse


def analyze_domain(url):
    """
    Perform structural domain analysis.

    This module does not make an HTTP request to the
    submitted website.
    """

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    result = {
        "hostname": hostname,
        "subdomain": None,
        "registered_domain": None,
        "domain": None,
        "public_suffix": None,
        "domain_parts": [],
        "tld": None,
        "is_valid_structure": False
    }

    if not hostname:
        return result

    # ----------------------------------------------
    # Split hostname
    # ----------------------------------------------

    parts = hostname.split(".")

    result["domain_parts"] = parts

    # ----------------------------------------------
    # Public suffix / registered domain extraction
    # ----------------------------------------------

    extracted = tldextract.extract(hostname)

    result["subdomain"] = (
        extracted.subdomain
        if extracted.subdomain
        else None
    )

    result["domain"] = (
        extracted.domain
        if extracted.domain
        else None
    )

    result["public_suffix"] = (
        extracted.suffix
        if extracted.suffix
        else None
    )

    # Registered domain
    if extracted.domain and extracted.suffix:
        result["registered_domain"] = (
            f"{extracted.domain}.{extracted.suffix}"
        )

    # TLD
    if extracted.suffix:
        result["tld"] = "." + extracted.suffix

    # ----------------------------------------------
    # Basic structural validation
    # ----------------------------------------------

    if (
        extracted.domain
        and extracted.suffix
        and len(extracted.domain) >= 1
    ):
        result["is_valid_structure"] = True

    return result