import os
import base64
import requests


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


def get_api_key():
    """
    Read the VirusTotal API key from the environment.
    """

    return os.getenv("VIRUSTOTAL_API_KEY")


def encode_url(url):
    """
    Create the unpadded Base64 URL identifier required
    by the VirusTotal URL report endpoint.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    return encoded.rstrip("=")


def analyze_reputation(url):
    """
    Retrieve an existing VirusTotal URL report.

    This function does NOT submit a new scan.
    It only requests an existing report.
    """

    api_key = get_api_key()

    result = {
        "configured": False,
        "found": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
        "total_engines": 0,
        "reputation": None,
        "error": None
    }

    # ------------------------------------------
    # API key check
    # ------------------------------------------

    if not api_key:

        result["error"] = (
            "VirusTotal API key is not configured."
        )

        return result

    result["configured"] = True

    # ------------------------------------------
    # Generate URL identifier
    # ------------------------------------------

    url_id = encode_url(url)

    endpoint = (
        f"{VIRUSTOTAL_API_URL}/urls/{url_id}"
    )

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=10
        )

        # --------------------------------------
        # Existing report found
        # --------------------------------------

        if response.status_code == 200:

            data = response.json()

            attributes = (
                data.get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            result["found"] = True

            result["malicious"] = stats.get(
                "malicious",
                0
            )

            result["suspicious"] = stats.get(
                "suspicious",
                0
            )

            result["harmless"] = stats.get(
                "harmless",
                0
            )

            result["undetected"] = stats.get(
                "undetected",
                0
            )

            result["timeout"] = stats.get(
                "timeout",
                0
            )

            result["total_engines"] = sum(
                stats.values()
            )

            result["reputation"] = attributes.get(
                "reputation"
            )

            return result

        # --------------------------------------
        # Report does not exist
        # --------------------------------------

        if response.status_code == 404:

            result["error"] = (
                "No existing VirusTotal report was found."
            )

            return result

        # --------------------------------------
        # Authentication problem
        # --------------------------------------

        if response.status_code == 401:

            result["error"] = (
                "VirusTotal API key is invalid."
            )

            return result

        # --------------------------------------
        # Rate limit
        # --------------------------------------

        if response.status_code == 429:

            result["error"] = (
                "VirusTotal API rate limit reached."
            )

            return result

        # --------------------------------------
        # Other API errors
        # --------------------------------------

        result["error"] = (
            f"VirusTotal API returned HTTP "
            f"{response.status_code}."
        )

        return result

    except requests.Timeout:

        result["error"] = (
            "VirusTotal request timed out."
        )

        return result

    except requests.RequestException as error:

        result["error"] = (
            f"VirusTotal connection error: {error}"
        )

        return result

    except Exception as error:

        result["error"] = str(error)

        return result