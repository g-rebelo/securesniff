import click
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.capture.live_capture import PacketCapture

@click.group()
def cli():
    """SecureSniff - Network Sniffer"""
    pass

@cli.command()
@click.option('--interface', '-i', default=None, help='Interface (ex: eth0, wlan0)')
@click.option('--count', '-c', default=0, help='Number of packets')
def capture(interface, count):
    """Start live capture"""
    sniffer = PacketCapture(interface=interface)
    sniffer.start(count=count)

if __name__ == '__main__':
    cli()