from collections import defaultdict, deque
from time import time
from typing import Any

from src.alerting import AlertManager
from src.config import (
    ALERT_COOLDOWN_SECONDS,
    AUTH_FAILURE_THRESHOLD,
    AUTH_FAILURE_WINDOW_SECONDS,
)


SERVICE_PORTS = {
    "SSH": 22,
    "SMB": 445,
    "RDP": 3389,
    "WINDOWS": None,
}


class AuthenticationMonitor:
    """Detects repeated authentication failures from security events."""

    def __init__(self, alert_manager: AlertManager | None = None) -> None:
        self.alert_manager = alert_manager or AlertManager()

        self.failure_history: dict[
            tuple[str, str], deque[dict[str, Any]]
        ] = defaultdict(deque)

        self.last_alert_time: dict[
            tuple[str, str], float
        ] = {}

    def process_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any] | None:
        event_id = str(event.get("event_id", ""))
        status = str(event.get("status", "")).lower()

        is_authentication_failure = (
            event_id == "4625"
            or status in {"failed", "failure", "denied"}
        )

        if not is_authentication_failure:
            return None

        timestamp = float(event.get("timestamp", time()))
        source_ip = str(event.get("source_ip", "unknown"))
        destination_ip = str(
            event.get("destination_ip", "local-host")
        )
        username = str(event.get("username", "unknown"))
        service = str(event.get("service", "WINDOWS")).upper()

        key = (source_ip, service)
        history = self.failure_history[key]

        history.append(
            {
                "timestamp": timestamp,
                "username": username,
                "event_id": event_id or "unknown",
            }
        )

        cutoff = timestamp - AUTH_FAILURE_WINDOW_SECONDS

        while history and history[0]["timestamp"] < cutoff:
            history.popleft()

        previous_alert = self.last_alert_time.get(key, 0.0)

        if (
            len(history) >= AUTH_FAILURE_THRESHOLD
            and timestamp - previous_alert
            >= ALERT_COOLDOWN_SECONDS
        ):
            self.last_alert_time[key] = timestamp

            usernames = sorted(
                {failure["username"] for failure in history}
            )

            return self.alert_manager.emit(
                event_type="BRUTE_FORCE",
                severity="HIGH",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=SERVICE_PORTS.get(service),
                protocol=service,
                description=(
                    f"{len(history)} failed {service} authentication "
                    f"attempts were observed within "
                    f"{AUTH_FAILURE_WINDOW_SECONDS} seconds."
                ),
                evidence={
                    "failure_count": len(history),
                    "usernames": usernames,
                    "window_seconds": AUTH_FAILURE_WINDOW_SECONDS,
                    "event_id": event_id or "unknown",
                },
            )

        return None