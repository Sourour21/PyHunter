import ipaddress
import os

import requests
from dotenv import load_dotenv

from app.enrichment.cache import IOC_Cache


load_dotenv()

VT_API_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 10


def get_vt_endpoint(ioc: str) -> str:
    """Return the VirusTotal API collection matching the IOC type."""

    try:
        ipaddress.ip_address(ioc)
        return "ip_addresses"
    except ValueError:
        return "domains"


class VirusTotalEnricher:
    def __init__(self, api_key: str | None = None, cache=None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.cache = cache or IOC_Cache()

    def enrich(self, ioc: str) -> dict:
        cached_result = self.cache.get(ioc)

        if cached_result is not None:
            return {
                **cached_result,
                "cached": True,
            }

        if not self.api_key:
            return {
                "ioc": ioc,
                "status": "OFFLINE",
                "message": "VirusTotal API key not configured",
                "cached": False,
            }

        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }

        try:
            response = requests.get(
                f"{VT_API_URL}/{get_vt_endpoint(ioc)}/{ioc}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

            response.raise_for_status()
            data = response.json()

            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            result = {
                "ioc": ioc,
                "status": "ANALYZED",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "cached": False,
            }

            self.cache.set(ioc, result)
            return result

        except requests.RequestException as error:
            return {
                "ioc": ioc,
                "status": "ERROR",
                "message": str(error),
                "cached": False,
            }
        except (ValueError, TypeError, AttributeError) as error:
            return {
                "ioc": ioc,
                "status": "ERROR",
                "message": str(error),
                "cached": False,
            }
