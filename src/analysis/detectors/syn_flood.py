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
logger = Logger()

class SynFloodDetector:
    def __init__(self):
        self.history = defaultdict(lambda: {'count': 0, 'start_time': 0})
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

                if data['count'] > self.RATE_LIMIT:
                    if src not in self.shown_alerts:
                        self.alert(src, data['count'])
                        self.shown_alerts.add(src)

    def alert(self, ip, count):
        msg = f"SYN FLOOD DETETADO! Origem: {ip} | Taxa: {count} pacotes/s"
        
        # 1. Mostrar no Ecrã
        console.print(f"\n[bold white on red] 🌊 {msg} [/]\n")
        
        # 2. Gravar no Ficheiro
        logger.log(msg)