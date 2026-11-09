import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.all import get_if_list

from src.auth_ingest import AuthenticationLogIngestor
from src.capture import PacketCapture, get_local_ipv4_addresses


console = Console()


def show_banner() -> None:
    console.print(
        r"""
[bold cyan]
   ______      __              ______
  / ____/_  __/ /_  ___  _____/ ____/_  _____
 / /   / / / / __ \/ _ \/ ___/ __/ / / / / _ \
/ /___/ /_/ / /_/ /  __/ /  / /___/ /_/ /  __/
\____/\__, /_.___/\___/_/  /_____/\__, /\___/
     /____/                       /____/
[/bold cyan]
[bold]Network Threat Detection and Splunk Alerting System[/bold]
[dim]Defensive security monitoring project[/dim]
"""
    )


def show_interfaces() -> None:
    table = Table(title="Available Network Interfaces")
    table.add_column("Number", style="cyan")
    table.add_column("Interface")

    for number, interface in enumerate(get_if_list(), start=1):
        table.add_row(str(number), interface)

    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture live network traffic, analyse a PCAP file, "
            "or process authentication security events."
        )
    )

    parser.add_argument(
        "--interface",
        help="Network interface used for live packet capture",
    )

    input_group = parser.add_mutually_exclusive_group()

    input_group.add_argument(
        "--pcap",
        type=Path,
        help="Analyse an existing PCAP or PCAPNG file",
    )

    input_group.add_argument(
        "--auth-log",
        type=Path,
        help="Analyse authentication events from a JSONL file",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        help="Stop live capture after this many seconds",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Stop after this many packets; zero means unlimited",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display the available network interfaces",
    )

    return parser


def analyse_authentication_log(log_path: Path) -> int:
    try:
        console.print(
            f"[green]Analysing authentication log:[/green] "
            f"{log_path}"
        )

        ingestor = AuthenticationLogIngestor()
        results = ingestor.analyse(log_path)

        console.print(
            f"\n[bold cyan]Authentication analysis summary[/bold cyan]\n"
            f"Events processed: {results['events_processed']}\n"
            f"Alerts generated: {results['alerts_generated']}\n"
            f"Invalid records: {results['invalid_records']}\n"
            f"Alert log: logs/alerts.jsonl"
        )

        return 0

    except Exception as error:
        console.print(f"[red]CyberEye error:[/red] {error}")
        return 1


def analyse_network_traffic(args: argparse.Namespace) -> int:
    capture = PacketCapture(interface=args.interface)

    console.print(
        f"[bold]Local IPv4 addresses:[/bold] "
        f"{', '.join(sorted(get_local_ipv4_addresses()))}"
    )

    exit_code = 0

    try:
        if args.pcap:
            console.print(
                f"[green]Analysing PCAP:[/green] {args.pcap}"
            )
            capture.analyse_pcap(args.pcap)

        else:
            selected_interface = args.interface or "Scapy default"

            console.print(
                f"[green]Starting live capture[/green]\n"
                f"Interface: {selected_interface}\n"
                f"Press Ctrl+C to stop.\n"
            )

            capture.capture_live(
                packet_limit=args.count,
                timeout=args.timeout,
            )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Capture stopped by user.[/yellow]"
        )

    except PermissionError:
        console.print(
            "[red]Permission denied. Run PowerShell or VS Code "
            "as Administrator.[/red]"
        )
        exit_code = 1

    except Exception as error:
        console.print(f"[red]CyberEye error:[/red] {error}")
        exit_code = 1

    finally:
        console.print(
            f"\n[bold cyan]Capture summary[/bold cyan]\n"
            f"Packets processed: {capture.packet_count}\n"
            f"Alerts generated: {capture.alert_count}\n"
            f"Packet log: logs/packets.csv\n"
            f"Alert log: logs/alerts.jsonl"
        )

    return exit_code


def main() -> int:
    show_banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        show_interfaces()
        return 0

    if args.auth_log:
        return analyse_authentication_log(args.auth_log)

    return analyse_network_traffic(args)


if __name__ == "__main__":
    sys.exit(main())