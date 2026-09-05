import socket
import ipaddress
from urllib.parse import urlparse


def analyze_dns(url):
    """
    Resolve the hostname associated with a URL and
    classify returned IP addresses.

    No HTTP request is made to the submitted website.
    """

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname

    result = {
        "hostname": hostname,
        "resolved": False,
        "ip_addresses": [],
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "public_addresses": [],
        "private_addresses": [],
        "error": None
    }

    if not hostname:
        result["error"] = "Could not extract hostname."
        return result

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        ip_addresses = sorted(
            set(
                address[4][0]
                for address in addresses
            )
        )

        result["ip_addresses"] = ip_addresses
        result["resolved"] = len(ip_addresses) > 0

        # ------------------------------------------
        # Classify IP addresses
        # ------------------------------------------

        for address in ip_addresses:

            try:
                ip = ipaddress.ip_address(address)

                if ip.version == 4:
                    result["ipv4_addresses"].append(address)

                elif ip.version == 6:
                    result["ipv6_addresses"].append(address)

                if ip.is_private:
                    result["private_addresses"].append(address)

                else:
                    result["public_addresses"].append(address)

            except ValueError:
                continue

    except socket.gaierror:

        result["error"] = (
            "Hostname could not be resolved."
        )

    except Exception as error:

        result["error"] = str(error)

    return result