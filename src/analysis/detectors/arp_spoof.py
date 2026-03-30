from scapy.layers.l2 import ARP, Ether
from rich.console import Console

console = Console()

class ArpSpoofDetector:
    def __init__(self):
        # Memória: Guarda o par {IP: MAC Address}
        # Exemplo: {'192.168.1.1': 'aa:bb:cc:11:22:33'}
        self.known_hosts = {}
        self.shown_alerts = set()

    def check(self, packet):
        # Só analisamos pacotes ARP (que servem para anunciar endereços)
        if ARP in packet and packet[ARP].op == 2: # op=2 significa "ARP Reply" (Resposta)
            real_ip = packet[ARP].psrc
            response_mac = packet[ARP].hwsrc

            # Se já conhecemos este IP...
            if real_ip in self.known_hosts:
                known_mac = self.known_hosts[real_ip]

                # ...e o MAC Address mudou de repente -> ATAQUE!
                if known_mac != response_mac:
                    if real_ip not in self.shown_alerts:
                        self.alert(real_ip, known_mac, response_mac)
                        self.shown_alerts.add(real_ip)
            
            # Se não conhecemos, guardamos para referência futura
            else:
                self.known_hosts[real_ip] = response_mac

    def alert(self, ip, old_mac, new_mac):
        console.print(f"\n[bold white on red] ☠️ ALERTA CRÍTICO: ARP SPOOFING (MITM) [/]")
        console.print(f"[bold red] >>> O dispositivo {ip} mudou de identidade![/]")
        console.print(f"[yellow]MAC Original: {old_mac}[/]")
        console.print(f"[yellow]MAC Falso (Atacante): {new_mac}[/]\n")