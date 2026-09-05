from urllib.parse import urlparse
import re


def extract_features(url):
    """
    Extract structural and lexical features from a URL.
    These features will later support both rule-based
    detection and machine-learning classification.
    """

    # Add a scheme if the user didn't provide one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    hostname = parsed.hostname or ""
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    features = {}

    # --------------------------------------------------
    # 1. BASIC URL FEATURES
    # --------------------------------------------------

    features["url_length"] = len(url)
    features["domain_length"] = len(hostname)
    features["path_length"] = len(path)

    # --------------------------------------------------
    # 2. PROTOCOL
    # --------------------------------------------------

    features["uses_https"] = int(parsed.scheme == "https")

    # --------------------------------------------------
    # 3. SPECIAL CHARACTERS
    # --------------------------------------------------

    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["question_mark_count"] = url.count("?")
    features["equals_count"] = url.count("=")
    features["ampersand_count"] = url.count("&")
    features["at_symbol"] = int("@" in url)

    # --------------------------------------------------
    # 4. DIGITS
    # --------------------------------------------------

    features["digit_count"] = sum(
        char.isdigit()
        for char in url
    )

    if len(url) > 0:
        features["digit_ratio"] = round(
            features["digit_count"] / len(url),
            3
        )
    else:
        features["digit_ratio"] = 0

    # --------------------------------------------------
    # 5. SUBDOMAINS
    # --------------------------------------------------

    if hostname:
        features["subdomain_count"] = max(
            len(hostname.split(".")) - 2,
            0
        )
    else:
        features["subdomain_count"] = 0

    # --------------------------------------------------
    # 6. IP ADDRESS DETECTION
    # --------------------------------------------------

    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    features["is_ip_address"] = int(
        bool(re.match(ipv4_pattern, hostname))
    )

    # --------------------------------------------------
    # 7. SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    suspicious_keywords = [
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "password",
        "credential",
        "bank",
        "banking",
        "confirm",
        "confirmation",
        "wallet",
        "payment",
        "invoice",
        "free",
        "bonus",
        "gift",
        "claim",
        "recover"
    ]

    url_lower = url.lower()

    found_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url_lower
    ]

    features["suspicious_keyword_count"] = len(
        found_keywords
    )

    # --------------------------------------------------
    # 8. URL ENCODING
    # --------------------------------------------------

    features["percent_encoding_count"] = url.count("%")

    # --------------------------------------------------
    # 9. QUERY PARAMETERS
    # --------------------------------------------------

    if query:
        features["query_parameter_count"] = len(
            query.split("&")
        )
    else:
        features["query_parameter_count"] = 0

    # --------------------------------------------------
    # 10. FRAGMENT
    # --------------------------------------------------

    features["has_fragment"] = int(
        bool(fragment)
    )

    # --------------------------------------------------
    # 11. DOUBLE SLASH
    # --------------------------------------------------

    remainder = re.sub(
        r"^https?://",
        "",
        url,
        flags=re.IGNORECASE
    )

    features["double_slash_in_path"] = int(
        "//" in remainder
    )

    # --------------------------------------------------
    # 12. PORT NUMBER
    # --------------------------------------------------

    try:
        features["has_port"] = int(
            parsed.port is not None
        )
    except ValueError:
        features["has_port"] = 0

    # --------------------------------------------------
    # 13. PUNYCODE / IDN
    # --------------------------------------------------

    features["has_punycode"] = int(
        "xn--" in hostname.lower()
    )

    # --------------------------------------------------
    # 14. URL SHORTENER
    # --------------------------------------------------

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly"
    ]

    features["is_url_shortener"] = int(
        hostname in shortener_domains
    )

    # --------------------------------------------------
    # 15. SUSPICIOUS TLD
    # --------------------------------------------------

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".link",
        ".work",
        ".zip",
        ".mov"
    ]

    features["suspicious_tld"] = int(
        any(
            hostname.endswith(tld)
            for tld in suspicious_tlds
        )
    )

    # --------------------------------------------------
    # 16. @ SYMBOL
    # --------------------------------------------------

    features["contains_at_symbol"] = int(
        "@" in url
    )

    # --------------------------------------------------
    # 17. SPECIAL CHARACTERS
    # --------------------------------------------------

    special_characters = sum(
        not char.isalnum()
        for char in url
    )

    features["special_character_count"] = (
        special_characters
    )

    # --------------------------------------------------
    # 18. DOMAIN DIGITS
    # --------------------------------------------------

    features["domain_digit_count"] = sum(
        char.isdigit()
        for char in hostname
    )

    # --------------------------------------------------
    # 19. DOMAIN HYPHENS
    # --------------------------------------------------

    features["domain_hyphen_count"] = (
        hostname.count("-")
    )

    # --------------------------------------------------
    # 20. BRAND-STYLE KEYWORDS
    # --------------------------------------------------

    brand_keywords = [
        "paypal",
        "microsoft",
        "apple",
        "google",
        "amazon",
        "facebook",
        "instagram",
        "netflix",
        "linkedin",
        "dropbox",
        "adobe",
        "steam"
    ]

    features["brand_keyword_count"] = sum(
        brand in hostname
        for brand in brand_keywords
    )

    return features