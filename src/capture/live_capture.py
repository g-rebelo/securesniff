from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP
from rich.console import Console
from datetime import datetime
import sys
import os

# Importar o detetor que acabaste de criar
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.analysis.detectors.port_scan import PortScanDetector

console = Console()

class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        # Ligar o detetor
        self.detector = PortScanDetector()

    def process_packet(self, packet):
        # 1. PRIMEIRO: Analisar se é ameaça
        try:
            self.detector.check(packet)
        except Exception as e:
            pass # Se der erro na analise, continua a mostrar o pacote

        # 2. DEPOIS: Mostrar no ecrã (igual a antes)
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_name = "OTHER"
            info = ""

            if TCP in packet:
                proto_name = "TCP"
                info = f"Port: {packet[TCP].sport} -> {packet[TCP].dport} | Flags: {packet[TCP].flags}"
            elif UDP in packet:
                proto_name = "UDP"
                info = f"Port: {packet[UDP].sport} -> {packet[UDP].dport}"
            elif ICMP in packet:
                proto_name = "ICMP"
                info = f"Type: {packet[ICMP].type}"

            color = "white"
            if proto_name == "TCP": color = "cyan"
            elif proto_name == "UDP": color = "magenta"
            elif proto_name == "ICMP": color = "yellow"

            timestamp = datetime.now().strftime("%H:%M:%S")
            console.print(f"[{timestamp}] [bold {color}]{proto_name:<5}[/] {src:<15} -> {dst:<15} | {info}")

    def start(self, count=0, filter_str=None):
        console.print(f"[bold green][*] SecureSniff com Deteção de Ameaças Ativo na interface: {self.interface}[/]")
        try:
            sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self.process_packet,
                filter=filter_str,
                store=False,
                count=count
            )
            sniffer.start()
            sniffer.join()
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Captura parada.[/]")