import csv
import socket
from pathlib import Path
from typing import Any

import psutil
from scapy.all import IP, TCP, UDP, sniff

from src.config import PACKET_LOG
from src.detectors import DetectionEngine


PACKET_FIELDS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "tcp_flags",
    "packet_length",
    "direction",
]


def get_local_ipv4_addresses() -> set[str]:
    """Return IPv4 addresses assigned to this computer."""

    addresses: set[str] = set()

    for interface_addresses in psutil.net_if_addrs().values():
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                addresses.add(address.address)

    return addresses


class PacketCapture:
    """Captures live packets or processes an existing PCAP file."""

    def __init__(
        self,
        detector: DetectionEngine | None = None,
        interface: str | None = None,
        packet_log: Path = PACKET_LOG,
    ) -> None:
        self.detector = detector or DetectionEngine()
        self.interface = interface
        self.packet_log = packet_log
        self.packet_log.parent.mkdir(parents=True, exist_ok=True)

        self.local_addresses = get_local_ipv4_addresses()
        self.packet_count = 0
        self.alert_count = 0
        self._csv_file = None
        self._csv_writer = None

    def capture_live(
        self,
        packet_limit: int = 0,
        timeout: int | None = None,
    ) -> None:
        """Capture live traffic. Zero packet_limit means no fixed limit."""

        self._open_packet_log()

        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                count=packet_limit,
                timeout=timeout,
            )
        finally:
            self._close_packet_log()

    def analyse_pcap(self, pcap_path: str | Path) -> None:
        """Process packets from a PCAP or PCAPNG file."""

        path = Path(pcap_path)

        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        self._open_packet_log()

        try:
            sniff(
                offline=str(path),
                prn=self._handle_packet,
                store=False,
            )
        finally:
            self._close_packet_log()

    def _handle_packet(self, packet: Any) -> None:
        if IP not in packet:
            return

        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        source_port = None
        destination_port = None
        protocol = "OTHER"
        tcp_flags = 0

        if TCP in packet:
            tcp_layer = packet[TCP]
            source_port = int(tcp_layer.sport)
            destination_port = int(tcp_layer.dport)
            protocol = "TCP"
            tcp_flags = int(tcp_layer.flags)

        elif UDP in packet:
            udp_layer = packet[UDP]
            source_port = int(udp_layer.sport)
            destination_port = int(udp_layer.dport)
            protocol = "UDP"

        direction = self._determine_direction(
            source_ip,
            destination_ip,
        )

        packet_record = {
            "timestamp": float(packet.time),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "tcp_flags": tcp_flags,
            "packet_length": len(packet),
            "direction": direction,
        }

        self.packet_count += 1
        self._write_packet(packet_record)

        alerts = self.detector.process(packet_record)
        self.alert_count += len(alerts)

    def _determine_direction(
        self,
        source_ip: str,
        destination_ip: str,
    ) -> str:
        source_is_local = source_ip in self.local_addresses
        destination_is_local = destination_ip in self.local_addresses

        if source_is_local and not destination_is_local:
            return "outbound"

        if destination_is_local and not source_is_local:
            return "inbound"

        if source_is_local and destination_is_local:
            return "local"

        return "unknown"

    def _open_packet_log(self) -> None:
        write_header = (
            not self.packet_log.exists()
            or self.packet_log.stat().st_size == 0
        )

        self._csv_file = self.packet_log.open(
            "a",
            newline="",
            encoding="utf-8",
        )
        self._csv_writer = csv.DictWriter(
            self._csv_file,
            fieldnames=PACKET_FIELDS,
        )

        if write_header:
            self._csv_writer.writeheader()

    def _write_packet(self, packet_record: dict[str, Any]) -> None:
        if self._csv_writer is not None:
            self._csv_writer.writerow(packet_record)

    def _close_packet_log(self) -> None:
        if self._csv_file is not None:
            self._csv_file.close()
            self._csv_file = None
            self._csv_writer = None