import os
import socket
from dotenv import load_dotenv
from typing import Any

import requests
load_dotenv()


class SplunkHECForwarder:
    """Forwards CyberEye alerts to Splunk HTTP Event Collector."""

    def __init__(
        self,
        hec_url: str | None = None,
        hec_token: str | None = None,
        index: str = "main",
        verify_ssl: bool = True,
        timeout: int = 5,
    ) -> None:
        self.hec_url = (hec_url or "").rstrip("/")
        self.hec_token = hec_token or ""
        self.index = index
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    @classmethod
    def from_environment(cls) -> "SplunkHECForwarder":
        verify_value = os.getenv(
            "SPLUNK_VERIFY_SSL",
            "true",
        ).lower()

        return cls(
            hec_url=os.getenv("SPLUNK_HEC_URL"),
            hec_token=os.getenv("SPLUNK_HEC_TOKEN"),
            index=os.getenv("SPLUNK_INDEX", "main"),
            verify_ssl=verify_value not in {
                "false",
                "0",
                "no",
            },
        )

    @property
    def enabled(self) -> bool:
        return bool(self.hec_url and self.hec_token)

    def send(self, alert: dict[str, Any]) -> bool:
        if not self.enabled:
            return False

        endpoint = self.hec_url

        if not endpoint.endswith("/services/collector/event"):
            endpoint += "/services/collector/event"

        payload = {
            "host": socket.gethostname(),
            "source": "cybereye",
            "sourcetype": "cybereye:alert",
            "index": self.index,
            "event": alert,
        }

        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

        response.raise_for_status()

        response_data = response.json()
        return response_data.get("code") == 0