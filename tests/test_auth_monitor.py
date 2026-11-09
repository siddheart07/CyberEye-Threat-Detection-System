from src.auth_monitor import AuthenticationMonitor


class FakeAlertManager:
    def __init__(self) -> None:
        self.alerts = []

    def emit(self, **alert):
        self.alerts.append(alert)
        return alert


def create_failure_event(
    timestamp: float,
    username: str = "administrator",
) -> dict:
    return {
        "timestamp": timestamp,
        "event_id": 4625,
        "status": "failed",
        "source_ip": "10.10.10.50",
        "destination_ip": "192.168.1.10",
        "username": username,
        "service": "RDP",
    }


def test_repeated_failures_trigger_brute_force_alert() -> None:
    alert_manager = FakeAlertManager()
    monitor = AuthenticationMonitor(alert_manager)

    for index in range(5):
        monitor.process_event(
            create_failure_event(
                timestamp=1000.0 + index,
                username=f"user{index}",
            )
        )

    assert len(alert_manager.alerts) == 1
    assert alert_manager.alerts[0]["event_type"] == "BRUTE_FORCE"
    assert alert_manager.alerts[0]["severity"] == "HIGH"
    assert alert_manager.alerts[0]["destination_port"] == 3389


def test_successful_login_is_ignored() -> None:
    alert_manager = FakeAlertManager()
    monitor = AuthenticationMonitor(alert_manager)

    result = monitor.process_event(
        {
            "timestamp": 2000.0,
            "event_id": 4624,
            "status": "success",
            "source_ip": "10.10.10.50",
            "username": "administrator",
            "service": "RDP",
        }
    )

    assert result is None
    assert alert_manager.alerts == []


def test_old_failures_are_removed_from_window() -> None:
    alert_manager = FakeAlertManager()
    monitor = AuthenticationMonitor(alert_manager)

    for index in range(4):
        monitor.process_event(
            create_failure_event(
                timestamp=3000.0 + index,
            )
        )

    monitor.process_event(
        create_failure_event(timestamp=4000.0)
    )

    assert alert_manager.alerts == []