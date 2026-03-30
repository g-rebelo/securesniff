from collections import defaultdict
from scapy.layers.inet import IP, TCP
from rich.console import Console
import time
import sys
import os

# Importar o Logger
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
from src.utils.logger import Logger

console = Console()
logger = Logger() # Criar o escrivão

class PortScanDetector:
    def __init__(self):
        self.history = defaultdict(lambda: {'ports': set(), 'last_time': 0})
        self.PORT_LIMIT = 15
        self.TIME_WINDOW = 10
        self.shown_alerts = set()

    def check(self, packet):
        if IP in packet and TCP in packet:
            src = packet[IP].src
            flags = packet[TCP].flags
            dst_port = packet[TCP].dport

            if flags == 'S':
                current_time = time.time()
                attacker = self.history[src]

                if current_time - attacker['last_time'] > self.TIME_WINDOW:
                    attacker['ports'].clear()

                attacker['ports'].add(dst_port)
                attacker['last_time'] = current_time

                if len(attacker['ports']) > self.PORT_LIMIT:
                    if src not in self.shown_alerts:
                        self.alert(src, len(attacker['ports']))
                        self.shown_alerts.add(src)

    def alert(self, ip, ports_count):
        msg = f"PORT SCAN DETETADO! Origem: {ip} | Portas: {ports_count}"
        
        # 1. Mostrar no Ecrã
        console.print(f"\n[bold white on red] 🚨 {msg} [/]\n")
        
        # 2. Gravar no Ficheiro
        logger.log(msg)