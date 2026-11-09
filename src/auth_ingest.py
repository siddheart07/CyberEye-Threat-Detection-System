import json
from pathlib import Path
from typing import Any

from src.auth_monitor import AuthenticationMonitor


class AuthenticationLogIngestor:
    """Processes authentication events stored as JSON Lines."""

    def __init__(
        self,
        monitor: AuthenticationMonitor | None = None,
    ) -> None:
        self.monitor = monitor or AuthenticationMonitor()
        self.event_count = 0
        self.alert_count = 0
        self.invalid_count = 0

    def analyse(self, log_path: str | Path) -> dict[str, int]:
        path = Path(log_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Authentication log not found: {path}"
            )

        with path.open("r", encoding="utf-8") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                line = line.strip()

                if not line:
                    continue

                try:
                    event: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError:
                    self.invalid_count += 1
                    continue

                self.event_count += 1

                alert = self.monitor.process_event(event)

                if alert:
                    self.alert_count += 1

        return {
            "events_processed": self.event_count,
            "alerts_generated": self.alert_count,
            "invalid_records": self.invalid_count,
        }