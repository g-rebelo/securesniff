from collections import defaultdict
from scapy.layers.inet import IP, TCP
from rich.console import Console
import time

console = Console()

class PortScanDetector:
    def __init__(self):
        # Memória: Guarda quem (IP) tocou em que portas
        self.history = defaultdict(lambda: {'ports': set(), 'last_time': 0})
        
        # REGRAS DO DETETOR
        self.PORT_LIMIT = 15      # Se tocar em mais de 15 portas...
        self.TIME_WINDOW = 10     # ...em menos de 10 segundos...
        self.shown_alerts = set() # (Para não repetir alertas infinitamente)

    def check(self, packet):
        """Analisa se o pacote faz parte de um scan"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            flags = packet[TCP].flags
            dst_port = packet[TCP].dport

            # S = SYN (Tentativa de conexão)
            if flags == 'S':
                current_time = time.time()
                attacker = self.history[src_ip]

                
                if current_time - attacker['last_time'] > self.TIME_WINDOW:
                    attacker['ports'].clear()

   
                attacker['ports'].add(dst_port)
                attacker['last_time'] = current_time

           
                if len(attacker['ports']) > self.PORT_LIMIT:
                    if src_ip not in self.shown_alerts:
                        self.alert(src_ip, len(attacker['ports']))
                        self.shown_alerts.add(src_ip)

    def alert(self, ip, ports_count):
        console.print(f"\n[bold white on red] ALERTA DE SEGURANÇA: PORT SCAN DETETADO! [/]")
        console.print(f"[bold red] >>> O IP {ip} tentou aceder a {ports_count} portas diferentes em poucos segundos![/]\n")