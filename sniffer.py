import time
import matplotlib.pyplot as plt
from scapy.all import sniff

# Variables pour le benchmark
packet_count = 0
start_time = time.time()

time_list = []
packet_count_list = []

def process_packet(packet):
    global packet_count
    global start_time

    print(packet.summary())
    packet_count += 1
    elapsed_time = time.time() - start_time
    time_list.append(elapsed_time)
    packet_count_list.append(packet_count)

    plt.plot(time_list, packet_count_list)
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Count')
    plt.title('Real-time Network Traffic Analysis')
    plt.pause(0.01)  

def stop_sniffing(signal, frame):
    print("CTRL+C detected. Stopping sniffing...")
    total_time = time.time() - start_time
    average_time_per_packet = total_time / packet_count if packet_count > 0 else 0
    print(f'Total time: {total_time} seconds')
    print(f'Average time per packet: {average_time_per_packet} seconds')
    plt.show()
    exit(0)

import signal
signal.signal(signal.SIGINT, stop_sniffing)

sniff(prn=process_packet, store=0)