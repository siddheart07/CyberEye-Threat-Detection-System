from collections import defaultdict, deque
from time import time
from typing import Any

from src.alerting import AlertManager
from src.config import (
    ALERT_COOLDOWN_SECONDS,
    PORT_SCAN_UNIQUE_PORT_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    SUSPICIOUS_PORTS,
    SYN_FLOOD_PACKET_THRESHOLD,
    SYN_FLOOD_WINDOW_SECONDS,
)


class DetectionEngine:
    """Stateful detection engine for network packet metadata."""

    def __init__(self, alert_manager: AlertManager | None = None) -> None:
        self.alert_manager = alert_manager or AlertManager()

        self.port_scan_history: dict[
            tuple[str, str], deque[tuple[float, int]]
        ] = defaultdict(deque)

        self.syn_history: dict[
            tuple[str, str], deque[float]
        ] = defaultdict(deque)

        self.last_alert_time: dict[
            tuple[str, str, str, int | None], float
        ] = {}

    def process(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        """Inspect one packet record and return any generated alerts."""

        alerts: list[dict[str, Any]] = []

        timestamp = float(packet.get("timestamp", time()))
        source_ip = packet.get("source_ip")
        destination_ip = packet.get("destination_ip")
        destination_port = packet.get("destination_port")
        protocol = str(packet.get("protocol", "")).upper()
        direction = str(packet.get("direction", "unknown")).lower()
        tcp_flags = int(packet.get("tcp_flags", 0))

        if not source_ip or not destination_ip:
            return alerts

        if protocol != "TCP" or destination_port is None:
            return alerts

        # A new TCP connection normally begins with SYN set and ACK unset.
        is_initial_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)

        if not is_initial_syn:
            return alerts

        port_scan_alert = self._detect_port_scan(
            timestamp,
            source_ip,
            destination_ip,
            int(destination_port),
        )
        if port_scan_alert:
            alerts.append(port_scan_alert)

        syn_flood_alert = self._detect_syn_flood(
            timestamp,
            source_ip,
            destination_ip,
            int(destination_port),
        )
        if syn_flood_alert:
            alerts.append(syn_flood_alert)

        service_alert = self._detect_suspicious_service(
            timestamp,
            source_ip,
            destination_ip,
            int(destination_port),
            direction,
        )
        if service_alert:
            alerts.append(service_alert)

        return alerts

    def _detect_port_scan(
        self,
        timestamp: float,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
    ) -> dict[str, Any] | None:
        key = (source_ip, destination_ip)
        history = self.port_scan_history[key]
        history.append((timestamp, destination_port))

        cutoff = timestamp - PORT_SCAN_WINDOW_SECONDS
        while history and history[0][0] < cutoff:
            history.popleft()

        unique_ports = sorted({port for _, port in history})

        if (
            len(unique_ports) >= PORT_SCAN_UNIQUE_PORT_THRESHOLD
            and self._alert_ready(
                "PORT_SCAN",
                source_ip,
                destination_ip,
                None,
                timestamp,
            )
        ):
            return self.alert_manager.emit(
                event_type="PORT_SCAN",
                severity="HIGH",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol="TCP",
                description=(
                    f"{len(unique_ports)} unique destination ports were "
                    f"contacted within {PORT_SCAN_WINDOW_SECONDS} seconds."
                ),
                evidence={
                    "unique_port_count": len(unique_ports),
                    "destination_ports": unique_ports,
                    "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                },
            )

        return None

    def _detect_syn_flood(
        self,
        timestamp: float,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
    ) -> dict[str, Any] | None:
        key = (source_ip, destination_ip)
        history = self.syn_history[key]
        history.append(timestamp)

        cutoff = timestamp - SYN_FLOOD_WINDOW_SECONDS
        while history and history[0] < cutoff:
            history.popleft()

        if (
            len(history) >= SYN_FLOOD_PACKET_THRESHOLD
            and self._alert_ready(
                "SYN_FLOOD",
                source_ip,
                destination_ip,
                destination_port,
                timestamp,
            )
        ):
            return self.alert_manager.emit(
                event_type="SYN_FLOOD",
                severity="CRITICAL",
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol="TCP",
                description=(
                    f"{len(history)} initial SYN packets were observed "
                    f"within {SYN_FLOOD_WINDOW_SECONDS} seconds."
                ),
                evidence={
                    "syn_packet_count": len(history),
                    "window_seconds": SYN_FLOOD_WINDOW_SECONDS,
                },
            )

        return None

    def _detect_suspicious_service(
        self,
        timestamp: float,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        direction: str,
    ) -> dict[str, Any] | None:
        if direction != "inbound" or destination_port not in SUSPICIOUS_PORTS:
            return None

        if not self._alert_ready(
            "SUSPICIOUS_SERVICE_ACCESS",
            source_ip,
            destination_ip,
            destination_port,
            timestamp,
        ):
            return None

        service_name = SUSPICIOUS_PORTS[destination_port]

        return self.alert_manager.emit(
            event_type="SUSPICIOUS_SERVICE_ACCESS",
            severity="MEDIUM",
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol="TCP",
            description=(
                f"Inbound connection attempt detected against "
                f"{service_name} on TCP port {destination_port}."
            ),
            evidence={
                "service": service_name,
                "direction": direction,
            },
        )

    def _alert_ready(
        self,
        event_type: str,
        source_ip: str,
        destination_ip: str,
        destination_port: int | None,
        timestamp: float,
    ) -> bool:
        key = (
            event_type,
            source_ip,
            destination_ip,
            destination_port,
        )
        previous = self.last_alert_time.get(key, 0.0)

        if timestamp - previous < ALERT_COOLDOWN_SECONDS:
            return False

        self.last_alert_time[key] = timestamp
        return True