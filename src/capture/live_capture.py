from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP
from rich.console import Console
from datetime import datetime
import sys
import os

# Adicionar caminho para encontrar os módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.analysis.detectors.port_scan import PortScanDetector
from src.analysis.detectors.syn_flood import SynFloodDetector
from src.analysis.detectors.arp_spoof import ArpSpoofDetector
from src.parser.http_parser import HTTPParser  # <--- CONFIRMA SE ISTO ESTÁ AQUI

console = Console()

class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        self.port_scan = PortScanDetector()
        self.syn_flood = SynFloodDetector()
        self.arp_spoof = ArpSpoofDetector()
        self.http_spy = HTTPParser() # O Espião

    def process_packet(self, packet):
        # 1. Detetar Ataques
        try:
            self.port_scan.check(packet)
            self.syn_flood.check(packet)
            self.arp_spoof.check(packet)
        except Exception as e:
            print(f"[ERRO DETECTOR]: {e}")

        # 2. Espiar HTTP (COM DEBUG)
        if packet.haslayer('Raw'): # Se o pacote tem "carga" (dados)
            # Descomenta a linha abaixo se quiseres ver SEMPRE que há dados
            # print("DEBUG: Pacote com dados encontrado!") 
            try:
                self.http_spy.process(packet)
            except Exception as e:
                print(f"[ERRO ESPIÃO]: {e}")

        # 3. Mostrar Tráfego Normal (Verde)
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
            timestamp = datetime.now().strftime("%H:%M:%S")
            # print simples para não encher o ecrã
            # console.print(f"[{timestamp}] [green]{proto}[/] {src} -> {dst}")

    def start(self, count=0, filter_str=None):
        console.print(f"[bold green][*] SecureSniff a correr na interface: {self.interface}[/]")
        # filter="tcp" ajuda a focar só em pacotes que podem ter passwords
        sniffer = AsyncSniffer(iface=self.interface, prn=self.process_packet, store=False, count=count, filter="tcp")
        sniffer.start()
        sniffer.join()