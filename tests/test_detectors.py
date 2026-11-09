from src.detectors import DetectionEngine


class FakeAlertManager:
    def __init__(self) -> None:
        self.alerts = []

    def emit(self, **alert):
        self.alerts.append(alert)
        return alert


def create_syn_packet(
    timestamp: float,
    destination_port: int,
    direction: str = "outbound",
) -> dict:
    return {
        "timestamp": timestamp,
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "destination_port": destination_port,
        "protocol": "TCP",
        "tcp_flags": 0x02,
        "direction": direction,
    }


def test_port_scan_detection() -> None:
    alert_manager = FakeAlertManager()
    detector = DetectionEngine(alert_manager)

    for index, port in enumerate(range(20, 28)):
        detector.process(
            create_syn_packet(
                timestamp=100.0 + index,
                destination_port=port,
            )
        )

    event_types = [
        alert["event_type"] for alert in alert_manager.alerts
    ]

    assert "PORT_SCAN" in event_types


def test_syn_flood_detection() -> None:
    alert_manager = FakeAlertManager()
    detector = DetectionEngine(alert_manager)

    for index in range(60):
        detector.process(
            create_syn_packet(
                timestamp=200.0 + (index * 0.01),
                destination_port=443,
            )
        )

    event_types = [
        alert["event_type"] for alert in alert_manager.alerts
    ]

    assert "SYN_FLOOD" in event_types


def test_suspicious_inbound_service_detection() -> None:
    alert_manager = FakeAlertManager()
    detector = DetectionEngine(alert_manager)

    detector.process(
        create_syn_packet(
            timestamp=300.0,
            destination_port=3389,
            direction="inbound",
        )
    )

    assert len(alert_manager.alerts) == 1
    assert (
        alert_manager.alerts[0]["event_type"]
        == "SUSPICIOUS_SERVICE_ACCESS"
    )
    assert alert_manager.alerts[0]["severity"] == "MEDIUM"


def test_normal_web_connection_has_no_alert() -> None:
    alert_manager = FakeAlertManager()
    detector = DetectionEngine(alert_manager)

    detector.process(
        create_syn_packet(
            timestamp=400.0,
            destination_port=443,
            direction="outbound",
        )
    )

    assert alert_manager.alerts == []