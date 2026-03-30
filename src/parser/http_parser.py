from scapy.layers.inet import TCP
from rich.console import Console

console = Console()

class HTTPParser:
    def process(self, packet):
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            try:
                # Tenta descodificar os bytes para texto
                payload_str = payload.decode('utf-8', 'ignore')
                
                # SE encontrar "user=" ou "pass=" ou "password=", IMPRIME LOGO!
                # Isto é mais agressivo para garantir que apanhamos o curl
                keywords = ["user=", "pass=", "username=", "password=", "login="]
                
                for word in keywords:
                    if word in payload_str.lower():
                        console.print(f"\n[bold white on blue] 🌐 DADOS SUSPEITOS ENCONTRADOS! [/]")
                        console.print(f"[bold red on yellow] 🔥 CONTEÚDO: [/] [yellow]{payload_str}[/]\n")
                        return # Pára de procurar neste pacote
                        
            except Exception as e:
                print(f"Erro ao ler pacote: {e}")