from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"

ALERT_LOG = LOG_DIR / "alerts.jsonl"
PACKET_LOG = LOG_DIR / "packets.csv"

# Detection windows and thresholds
PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 8

SYN_FLOOD_WINDOW_SECONDS = 5
SYN_FLOOD_PACKET_THRESHOLD = 60

CONNECTION_BURST_WINDOW_SECONDS = 10
CONNECTION_BURST_THRESHOLD = 100

ALERT_COOLDOWN_SECONDS = 15
AUTH_FAILURE_WINDOW_SECONDS = 60
AUTH_FAILURE_THRESHOLD = 5

# Commonly targeted services
SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
}

# MITRE ATT&CK mappings
MITRE_MAPPINGS = {
    "PORT_SCAN": {
        "technique": "T1046",
        "name": "Network Service Discovery",
    },
    "SYN_FLOOD": {
        "technique": "T1498",
        "name": "Network Denial of Service",
    },
    "CONNECTION_BURST": {
        "technique": "T1046",
        "name": "Network Service Discovery",
    },
    "SUSPICIOUS_SERVICE_ACCESS": {
        "technique": "T1021",
        "name": "Remote Services",
            "BRUTE_FORCE": {
        "technique": "T1110",
        "name": "Brute Force",
    },
    },
}

LOG_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)