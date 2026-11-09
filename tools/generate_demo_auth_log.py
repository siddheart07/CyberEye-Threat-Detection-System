import json
from pathlib import Path
from time import time


OUTPUT_FILE = Path("data/demo_auth_events.jsonl")


def main() -> None:
    base_time = time()

    events = [
        {
            "timestamp": base_time,
            "event_id": 4624,
            "status": "success",
            "source_ip": "10.10.10.25",
            "destination_ip": "192.168.1.10",
            "username": "ram",
            "service": "RDP",
        }
    ]

    for index in range(6):
        events.append(
            {
                "timestamp": base_time + 10 + index,
                "event_id": 4625,
                "status": "failed",
                "source_ip": "10.10.10.50",
                "destination_ip": "192.168.1.10",
                "username": "administrator",
                "service": "RDP",
            }
        )

    OUTPUT_FILE.parent.mkdir(exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for event in events:
            output.write(json.dumps(event) + "\n")

    print(f"Created {OUTPUT_FILE}")
    print(f"Events written: {len(events)}")
    print("Contains one successful login and six failed RDP logins.")


if __name__ == "__main__":
    main()