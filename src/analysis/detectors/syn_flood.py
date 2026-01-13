from collections import defaultdict
from scapy.layers.inet import IP, TCP
from rich.console import Console
import time

console = Console()

class SynFloodDetector:
    def __init__(self):
        # Memória: Quantos pacotes SYN este IP enviou para esta porta?
        # Formato: {'IP_SRC': {'count': 0, 'start_time': 12345}}
        self.history = defaultdict(lambda: {'count': 0, 'start_time': 0})
        
        # REGRAS (Thresholds)
        self.RATE_LIMIT = 100   
        self.TIME_WINDOW = 1     
        self.shown_alerts = set()

    def check(self, packet):
        if IP in packet and TCP in packet:
            src = packet[IP].src
            flags = packet[TCP].flags
            
            if flags == 'S':
                current_time = time.time()
                data = self.history[src]

                if current_time - data['start_time'] > self.TIME_WINDOW:
                    data['count'] = 0
                    data['start_time'] = current_time

                data['count'] += 1

                # VERIFICA SE É FLOOD
                if data['count'] > self.RATE_LIMIT:
                    if src not in self.shown_alerts:
                        self.alert(src, data['count'])
                        # Adiciona aos alertas mostrados para não spammar o terminal
                        self.shown_alerts.add(src)

    def alert(self, ip, count):
        console.print(f"\n[bold white on red] 🌊 ALERTA CRÍTICO: SYN FLOOD DETETADO! [/]")
        console.print(f"[bold red] >>> O IP {ip} está a enviar {count} pacotes/segundo! Possível DoS.[/]\n")