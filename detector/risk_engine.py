def calculate_risk(
    features,
    dns_result=None,
    domain_result=None,
    reputation_result=None,
    ml_result=None
):
    """
    Ensemble phishing risk engine.

    Components:
        - Rule-based URL analysis
        - DNS analysis
        - Domain analysis
        - Machine-learning prediction
        - VirusTotal reputation

    Final score:
        0-29   = Likely Safe
        30-59  = Suspicious
        60-100 = Likely Phishing
    """

    # =========================================================
    # RULE-BASED ANALYSIS
    # =========================================================

    rule_score = 0
    indicators = []

    # ---------------------------------------------------------
    # HTTPS
    # ---------------------------------------------------------

    if features.get("uses_https", 0) == 0:
        rule_score += 10

        indicators.append({
            "severity": "medium",
            "title": "HTTPS Not Detected",
            "description": (
                "The URL does not use HTTPS. "
                "HTTPS alone does not determine whether "
                "a website is legitimate."
            )
        })

    # ---------------------------------------------------------
    # IP ADDRESS
    # ---------------------------------------------------------

    if features.get("is_ip_address", 0) == 1:
        rule_score += 25

        indicators.append({
            "severity": "high",
            "title": "IP Address Used",
            "description": (
                "The URL uses an IP address instead "
                "of a conventional domain name."
            )
        })

    # ---------------------------------------------------------
    # LONG URL
    # ---------------------------------------------------------

    if features.get("url_length", 0) > 75:
        rule_score += 10

        indicators.append({
            "severity": "low",
            "title": "Long URL",
            "description": (
                "The URL is unusually long."
            )
        })

    # ---------------------------------------------------------
    # SUBDOMAINS
    # ---------------------------------------------------------

    if features.get("subdomain_count", 0) >= 3:
        rule_score += 15

        indicators.append({
            "severity": "medium",
            "title": "Multiple Subdomains",
            "description": (
                "The URL contains several subdomains."
            )
        })

    # ---------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    keyword_count = features.get(
        "suspicious_keyword_count",
        0
    )

    if keyword_count >= 3:
        rule_score += 20

        indicators.append({
            "severity": "high",
            "title": "Multiple Suspicious Keywords",
            "description": (
                f"{keyword_count} phishing-related "
                "keyword(s) were detected."
            )
        })

    elif keyword_count > 0:
        rule_score += 8

        indicators.append({
            "severity": "low",
            "title": "Suspicious Keyword",
            "description": (
                f"{keyword_count} potentially suspicious "
                "keyword(s) were detected."
            )
        })

    # ---------------------------------------------------------
    # @ SYMBOL
    # ---------------------------------------------------------

    if features.get("contains_at_symbol", 0) == 1:
        rule_score += 20

        indicators.append({
            "severity": "high",
            "title": "URL Contains @ Symbol",
            "description": (
                "The @ character can be abused to obscure "
                "the actual destination hostname."
            )
        })

    # ---------------------------------------------------------
    # URL ENCODING
    # ---------------------------------------------------------

    if features.get(
        "percent_encoding_count",
        0
    ) >= 3:
        rule_score += 10

        indicators.append({
            "severity": "medium",
            "title": "Excessive URL Encoding",
            "description": (
                "The URL contains multiple "
                "percent-encoded characters."
            )
        })

    # ---------------------------------------------------------
    # SUSPICIOUS TLD
    # ---------------------------------------------------------

    if features.get("suspicious_tld", 0) == 1:
        rule_score += 8

        indicators.append({
            "severity": "low",
            "title": "Unusual Top-Level Domain",
            "description": (
                "The domain uses a TLD that may "
                "warrant additional investigation."
            )
        })

    # ---------------------------------------------------------
    # PUNYCODE
    # ---------------------------------------------------------

    if features.get("has_punycode", 0) == 1:
        rule_score += 20

        indicators.append({
            "severity": "high",
            "title": "Punycode Domain",
            "description": (
                "The domain contains Punycode, which can "
                "be associated with homograph attacks."
            )
        })

    # ---------------------------------------------------------
    # URL SHORTENER
    # ---------------------------------------------------------

    if features.get("is_url_shortener", 0) == 1:
        rule_score += 10

        indicators.append({
            "severity": "medium",
            "title": "URL Shortener Detected",
            "description": (
                "The URL uses a shortening service "
                "that can conceal the final destination."
            )
        })

    # ---------------------------------------------------------
    # DOMAIN HYPHENS
    # ---------------------------------------------------------

    if features.get(
        "domain_hyphen_count",
        0
    ) >= 3:
        rule_score += 8

        indicators.append({
            "severity": "low",
            "title": "Multiple Domain Hyphens",
            "description": (
                "The domain contains several hyphens."
            )
        })

    # ---------------------------------------------------------
    # DOMAIN DIGITS
    # ---------------------------------------------------------

    if features.get(
        "domain_digit_count",
        0
    ) >= 4:
        rule_score += 8

        indicators.append({
            "severity": "low",
            "title": "Many Digits in Domain",
            "description": (
                "The domain contains an unusually "
                "high number of digits."
            )
        })

    # ---------------------------------------------------------
    # PORT
    # ---------------------------------------------------------

    if features.get("has_port", 0) == 1:
        rule_score += 5

        indicators.append({
            "severity": "low",
            "title": "Explicit Port Number",
            "description": (
                "The URL explicitly specifies a port number."
            )
        })

    # ---------------------------------------------------------
    # DOUBLE SLASH
    # ---------------------------------------------------------

    if features.get(
        "double_slash_in_path",
        0
    ) == 1:
        rule_score += 10

        indicators.append({
            "severity": "medium",
            "title": "Double Slash in Path",
            "description": (
                "The URL contains an additional double "
                "slash outside the protocol."
            )
        })

    # =========================================================
    # DNS ANALYSIS
    # =========================================================

    if dns_result:

        if not dns_result.get(
            "resolved",
            False
        ):
            rule_score += 5

            indicators.append({
                "severity": "medium",
                "title": "DNS Resolution Failed",
                "description": (
                    "The hostname could not be resolved "
                    "through DNS at analysis time."
                )
            })

        private_addresses = dns_result.get(
            "private_addresses",
            []
        )

        if private_addresses:
            rule_score += 10

            indicators.append({
                "severity": "medium",
                "title": "Private IP Address Detected",
                "description": (
                    "DNS resolution returned a private "
                    "network address."
                )
            })

    # =========================================================
    # DOMAIN ANALYSIS
    # =========================================================

    if domain_result:

        if not domain_result.get(
            "is_valid_structure",
            False
        ):
            rule_score += 10

            indicators.append({
                "severity": "medium",
                "title": "Unusual Domain Structure",
                "description": (
                    "The hostname does not appear to have "
                    "a conventional domain structure."
                )
            })

    # Cap rule score
    rule_score = min(
        rule_score,
        100
    )

    # =========================================================
    # MACHINE LEARNING
    # =========================================================

    ml_score = None

    if ml_result:

        if ml_result.get(
            "model_available",
            False
        ):

            phishing_probability = (
                ml_result.get(
                    "phishing_probability"
                )
            )

            if phishing_probability is not None:

                ml_score = float(
                    phishing_probability
                )

                prediction = ml_result.get(
                    "prediction"
                )

                if prediction == 1:

                    indicators.append({
                        "severity": "high",
                        "title": "Machine Learning Detection",
                        "description": (
                            f"The Random Forest model classified "
                            f"the URL as potentially phishing with "
                            f"{ml_score:.2f}% phishing probability."
                        )
                    })

                else:

                    indicators.append({
                        "severity": "low",
                        "title": "Machine Learning Detection",
                        "description": (
                            f"The Random Forest model classified "
                            f"the URL as likely legitimate with "
                            f"{100 - ml_score:.2f}% legitimate probability."
                        )
                    })

        elif ml_result.get("error"):

            indicators.append({
                "severity": "medium",
                "title": "ML Analysis Unavailable",
                "description": ml_result["error"]
            })

    # =========================================================
    # VIRUSTOTAL REPUTATION
    # =========================================================

    reputation_score = None

    if reputation_result:

        configured = reputation_result.get(
            "configured",
            False
        )

        found = reputation_result.get(
            "found",
            False
        )

        malicious = reputation_result.get(
            "malicious",
            0
        )

        suspicious = reputation_result.get(
            "suspicious",
            0
        )

        total_engines = reputation_result.get(
            "total_engines",
            0
        )

        # -----------------------------------------------------
        # Existing VirusTotal report
        # -----------------------------------------------------

        if configured and found:

            if total_engines > 0:

                malicious_ratio = (
                    malicious
                    / total_engines
                )

                suspicious_ratio = (
                    suspicious
                    / total_engines
                )

                reputation_score = min(
                    (
                        malicious_ratio * 100
                    )
                    +
                    (
                        suspicious_ratio * 40
                    ),
                    100
                )

            else:

                reputation_score = 0

            # -------------------------------------------------
            # Malicious detections
            # -------------------------------------------------

            if malicious >= 5:

                indicators.append({
                    "severity": "high",
                    "title": "Strong Malicious Reputation",
                    "description": (
                        f"VirusTotal reports {malicious} "
                        "security engine(s) detecting "
                        "the URL as malicious."
                    )
                })

            elif malicious >= 2:

                indicators.append({
                    "severity": "high",
                    "title": "Malicious Reputation Detected",
                    "description": (
                        f"VirusTotal reports {malicious} "
                        "malicious detection(s)."
                    )
                })

            elif malicious == 1:

                indicators.append({
                    "severity": "medium",
                    "title": "Potential Malicious Detection",
                    "description": (
                        "One VirusTotal security engine "
                        "reported the URL as malicious."
                    )
                })

            # -------------------------------------------------
            # Suspicious detections
            # -------------------------------------------------

            if suspicious > 0:

                indicators.append({
                    "severity": "medium",
                    "title": "Suspicious Reputation",
                    "description": (
                        f"VirusTotal reports {suspicious} "
                        "suspicious detection(s)."
                    )
                })

        # -----------------------------------------------------
        # No VirusTotal report
        # -----------------------------------------------------

        elif configured and not found:

            indicators.append({
                "severity": "low",
                "title": "No Existing Reputation Report",
                "description": (
                    "VirusTotal does not currently have "
                    "an existing report for this URL. "
                    "This does not mean the URL is safe."
                )
            })

        # -----------------------------------------------------
        # VirusTotal not configured
        # -----------------------------------------------------

        elif not configured:

            indicators.append({
                "severity": "low",
                "title": "Reputation Intelligence Unavailable",
                "description": (
                    "VirusTotal API credentials are not "
                    "configured, so external reputation "
                    "intelligence was not included."
                )
            })

    # =========================================================
    # ENSEMBLE WEIGHTS
    # =========================================================

    RULE_WEIGHT = 0.40
    ML_WEIGHT = 0.40
    REPUTATION_WEIGHT = 0.20

    weighted_score = 0
    total_weight = 0

    # ---------------------------------------------------------
    # Rules
    # ---------------------------------------------------------

    weighted_score += (
        rule_score
        * RULE_WEIGHT
    )

    total_weight += RULE_WEIGHT

    # ---------------------------------------------------------
    # Machine Learning
    # ---------------------------------------------------------

    if ml_score is not None:

        weighted_score += (
            ml_score
            * ML_WEIGHT
        )

        total_weight += ML_WEIGHT

    # ---------------------------------------------------------
    # Reputation
    # ---------------------------------------------------------

    if reputation_score is not None:

        weighted_score += (
            reputation_score
            * REPUTATION_WEIGHT
        )

        total_weight += REPUTATION_WEIGHT

    # ---------------------------------------------------------
    # Normalize
    # ---------------------------------------------------------

    if total_weight > 0:

        final_score = (
            weighted_score
            / total_weight
        )

    else:

        final_score = rule_score

    final_score = round(
        min(
            max(
                final_score,
                0
            ),
            100
        ),
        2
    )

    # =========================================================
    # CLASSIFICATION
    # =========================================================

    if final_score >= 60:

        classification = "Likely Phishing"
        severity = "HIGH"

    elif final_score >= 30:

        classification = "Suspicious"
        severity = "MEDIUM"

    else:

        classification = "Likely Safe"
        severity = "LOW"

    # =========================================================
    # CONFIDENCE
    # =========================================================

    available_scores = [
        rule_score
    ]

    if ml_score is not None:
        available_scores.append(
            ml_score
        )

    if reputation_score is not None:
        available_scores.append(
            reputation_score
        )

    if len(available_scores) >= 2:

        average_score = (
            sum(available_scores)
            / len(available_scores)
        )

        deviation = (
            sum(
                abs(
                    value
                    - average_score
                )
                for value in available_scores
            )
            / len(available_scores)
        )

        confidence = (
            95
            - deviation * 0.5
        )

        confidence = max(
            55,
            min(
                confidence,
                95
            )
        )

    else:

        confidence = 60

    confidence = round(
        confidence,
        2
    )

    # =========================================================
    # RETURN RESULT
    # =========================================================

    return {
        "score": final_score,

        "classification": classification,

        "severity": severity,

        "confidence": confidence,

        "indicators": indicators,

        "components": {
            "rule_score": round(
                rule_score,
                2
            ),

            "ml_score": (
                round(
                    ml_score,
                    2
                )
                if ml_score is not None
                else None
            ),

            "reputation_score": (
                round(
                    reputation_score,
                    2
                )
                if reputation_score is not None
                else None
            ),

            "rule_weight": RULE_WEIGHT,

            "ml_weight": (
                ML_WEIGHT
                if ml_score is not None
                else 0
            ),

            "reputation_weight": (
                REPUTATION_WEIGHT
                if reputation_score is not None
                else 0
            )
        }
    }