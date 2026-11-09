import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

from src.config import ALERT_LOG, MITRE_MAPPINGS
from src.splunk_forwarder import SplunkHECForwarder


class AlertManager:
    """Creates, displays, stores and optionally forwards alerts."""

    def __init__(
        self,
        log_path: Path = ALERT_LOG,
        splunk_forwarder: SplunkHECForwarder | None = None,
    ) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.console = Console()

        self.splunk_forwarder = (
            splunk_forwarder
            or SplunkHECForwarder.from_environment()
        )

    def emit(
        self,
        event_type: str,
        severity: str,
        source_ip: str,
        destination_ip: str,
        destination_port: int | None,
        protocol: str,
        description: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        mitre = MITRE_MAPPINGS.get(
            event_type,
            {
                "technique": "N/A",
                "name": "Unmapped Activity",
            },
        )

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity.upper(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "description": description,
            "mitre_technique": mitre["technique"],
            "mitre_technique_name": mitre["name"],
            "evidence": evidence or {},
            "sensor": "CyberEye",
        }

        self._write_to_jsonl(alert)
        self._display(alert)
        self._forward_to_splunk(alert)

        return alert

    def _write_to_jsonl(
        self,
        alert: dict[str, Any],
    ) -> None:
        with self.log_path.open(
            "a",
            encoding="utf-8",
        ) as log_file:
            log_file.write(json.dumps(alert) + "\n")

    def _forward_to_splunk(
        self,
        alert: dict[str, Any],
    ) -> None:
        if not self.splunk_forwarder.enabled:
            return

        try:
            forwarded = self.splunk_forwarder.send(alert)

            if forwarded:
                self.console.print(
                    "[green]Alert forwarded to Splunk HEC.[/green]"
                )
            else:
                self.console.print(
                    "[yellow]Splunk did not confirm the alert.[/yellow]"
                )

        except Exception as error:
            # Local logging must continue even when Splunk is unavailable.
            self.console.print(
                f"[yellow]Splunk forwarding failed:[/yellow] {error}"
            )

    def _display(
        self,
        alert: dict[str, Any],
    ) -> None:
        colours = {
            "LOW": "cyan",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold white on red",
        }

        colour = colours.get(
            alert["severity"],
            "white",
        )

        message = (
            f"[bold]Source:[/bold] {alert['source_ip']}\n"
            f"[bold]Destination:[/bold] "
            f"{alert['destination_ip']}:"
            f"{alert['destination_port']}\n"
            f"[bold]Protocol:[/bold] {alert['protocol']}\n"
            f"[bold]Description:[/bold] "
            f"{alert['description']}\n"
            f"[bold]MITRE ATT&CK:[/bold] "
            f"{alert['mitre_technique']} — "
            f"{alert['mitre_technique_name']}"
        )

        self.console.print(
            Panel(
                message,
                title=(
                    f"[{colour}]{alert['severity']} — "
                    f"{alert['event_type']}[/{colour}]"
                ),
                border_style=colour,
            )
        )