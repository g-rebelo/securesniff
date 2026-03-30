import click
import sys
import os

# Adicionar a pasta raiz ao caminho do Python para encontrar os módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importar as nossas ferramentas
from src.capture.live_capture import PacketCapture
from src.report.generator import ReportGenerator  # <--- ESTA LINHA FALTAVA

@click.group()
def cli():
    """SecureSniff - Ferramenta de Monitorização de Rede"""
    pass

# --- COMANDO 1: CAPTURAR ---
@cli.command()
@click.option('--interface', '-i', default=None, help='Interface de rede (ex: enp2s0, wlan0)')
@click.option('--count', '-c', default=0, help='Número de pacotes a capturar (0 = infinito)')
def capture(interface, count):
    """Iniciar a captura de pacotes em tempo real"""
    if not interface:
        print("Erro: Tens de escolher uma interface (ex: --interface enp2s0)")
        return
    sniffer = PacketCapture(interface=interface)
    sniffer.start(count=count)

# --- COMANDO 2: RELATÓRIO (O QUE FALTAVA) ---
@cli.command()
def report():
    """Gerar Relatório HTML com gráficos"""
    try:
        gen = ReportGenerator()
        gen.generate()
    except Exception as e:
        print(f"Erro ao gerar relatório: {e}")

if __name__ == '__main__':
    cli()