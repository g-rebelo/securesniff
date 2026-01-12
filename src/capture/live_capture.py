from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP
from rich.consolo import Console
from datetime import datetime

console = Console()

class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface

    def process_packet_(self, packet):
        #esta função vai servir para correr cada pacote
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_name = "OTHER"
            info = ""

            if TCP in packet:
                proto_name = "TCP"
                info = f"Port: {packet[TCP].sport} -> {packet[TCP].dport} | Flags: {packet[TCP].FLAGS}"
                elif UDP in packet:
                proto_name = "UDP"
                info = f"Porta: {packet[UDP].sport} -> {packet[UDP].dport}"
            elif ICMP in packet:
                proto_name = "ICMP"
                info = f"Tipo: {packet[ICMP].type}"

                color = "white"
                if proto_name == "TCP": color = "cyan"
                elif proto_name == "UDP": color = "magenta"
                elif pronto_name == "CNMP": color = "yellow"

                timestamp = datetime.now().strftime("%H:%M:%S")
                console.print(f"[{timestamp}]) [bold {color}]{proto_name:<5}[/] {src:<15} -> {dst:<15} | {info}")

def start(self, count = 0, filter_str=None):
    #inicia captura
    console.print(f"[bold green][*] Starting capture in the interface: {self.interface or 'padrao'}[/]")
        
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
            console.print("\n[bold red][!] Stopped capture.[/]")

            