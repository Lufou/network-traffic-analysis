from scapy.all import IP, ICMP, send

def generate_network_traffic(destination_ip, packet_count):
    # Crée un paquet ICMP (ping) vers l'adresse de destination spécifiée
    packet = IP(dst=destination_ip) / ICMP()

    # Envoie le paquet spécifié un certain nombre de fois
    send(packet, count=packet_count)

if __name__ == "__main__":
    destination_ip = "0.0.0.0"  # Remplacez par l'adresse IP de votre choix
    packet_count = 10  # Nombre de paquets à envoyer

    generate_network_traffic(destination_ip, packet_count)
