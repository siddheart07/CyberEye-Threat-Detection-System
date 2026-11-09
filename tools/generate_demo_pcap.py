from time import time

from scapy.all import IP, TCP, wrpcap


OUTPUT_FILE = "data/demo_attack_traffic.pcap"
SOURCE_IP = "10.10.10.50"
TARGET_IP = "192.168.1.10"


def create_demo_packets():
    packets = []
    base_time = time()

    # Normal HTTPS connection
    normal_packet = (
        IP(src=SOURCE_IP, dst=TARGET_IP)
        / TCP(sport=40000, dport=443, flags="S")
    )
    normal_packet.time = base_time
    packets.append(normal_packet)

    # Port-scan pattern: multiple unique destination ports
    scan_ports = [
        21,
        22,
        23,
        25,
        80,
        135,
        139,
        445,
        3389,
        5900,
    ]

    for index, port in enumerate(scan_ports):
        packet = (
            IP(src=SOURCE_IP, dst=TARGET_IP)
            / TCP(
                sport=41000 + index,
                dport=port,
                flags="S",
            )
        )
        packet.time = base_time + 1 + (index * 0.2)
        packets.append(packet)

    # SYN-flood pattern against TCP port 8080
    for index in range(65):
        packet = (
            IP(src=SOURCE_IP, dst=TARGET_IP)
            / TCP(
                sport=42000 + index,
                dport=8080,
                flags="S",
            )
        )
        packet.time = base_time + 4 + (index * 0.02)
        packets.append(packet)

    return packets


def main() -> None:
    packets = create_demo_packets()
    wrpcap(OUTPUT_FILE, packets)

    print(f"Created {OUTPUT_FILE}")
    print(f"Packets written: {len(packets)}")
    print("Contains normal traffic, a port scan and a SYN flood.")


if __name__ == "__main__":
    main()