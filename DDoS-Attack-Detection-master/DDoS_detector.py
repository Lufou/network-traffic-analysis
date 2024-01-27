## James Quintero
## https://github.com/JamesQuintero
## Created: 5/2019
## Modified: 4/2021
##
## Handles all the data required for the program

import sys
import os
import time
from data_handler import DataHandler
from ANN import ANN
import threading
import asyncio
from scapy.all import sniff, wrpcap
import warnings
#from sklearn.exceptions import InconsistentVersionWarning
#warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
from tensorflow import keras
Callback = keras.callbacks.Callback

class PerformanceCallback(Callback):
		total_time = 0
		time_per_step = 0

		def on_predict_begin(self, logs=None):
			self.start_time = time.time_ns()
			self.steps = 0

		def on_predict_batch_end(self, batch, logs=None):
			self.steps += 1

		def on_predict_end(self, logs=None):
			self.total_time = time.time_ns() - self.start_time
			self.time_per_step = self.total_time / self.steps if self.steps > 0 else 0

class DDoSDetector:

	#DataHandler class object
	data_handler = None

	#ANN class object
	neural_network = None
	must_clear = False
	captured_packets = None
	stats_file = None
	stop_capture_thread = None
	perf = None

	def __init__(self):
		self.data_handler = DataHandler()
		self.neural_network = ANN()
		self.captured_packets = []
		self.must_clear = False
		self.stop_capture_thread = threading.Event()
		if not os.path.isdir("./Stats"):
			os.mkdir("./Stats")
		self.stats_file = open(f"./Stats/{time.strftime('%Y%m%d%H%M%S')}.csv", 'w')
		self.perf = PerformanceCallback()


	def train(self, dataset_index, pcap_index=None):
		print("Dataset: "+str(self.data_handler.get_dataset_path(dataset_index)))
		if pcap_index!=None:
			print("PCAP: "+str(self.data_handler.get_pcap_path(dataset_index, pcap_index)))

		packets = []
		labels = []

		packets = self.data_handler.get_packet_information(dataset_index, pcap_index)
		labels = self.data_handler.get_labels(dataset_index, pcap_index)

		#turns each packet data from dictionaries into a flat 1d list. 
		compressed_packets = self.data_handler.compress_packets(packets)

		#takes compressed packet data and returns input variables values for neural network
		input_data = self.data_handler.generate_input_data(compressed_packets)

		#takes input variables and labels, and normalizes them
		normalized_input, normalized_output = self.data_handler.normalize_compressed_packets(input_data, labels, dataset_index)


		print("Num packets: "+str(len(normalized_input)))
		print("Num labels: "+str(len(normalized_output)))
		print("These should match")

		num_true_labels = sum([ label for label in normalized_output ])
		print("Num true labels: {}".format(num_true_labels))
		print("Num false labels: {}".format(len(normalized_output) - num_true_labels))


		#feeds input data and output data into the neural network
		self.neural_network.train_model(normalized_input, normalized_output, dataset_index)



	#dataset_index can specify a dataset to predict on, or if None, 
	# will represent predicting on live packets from "./Live sniffing"
	def predict(self, dataset_index=None, pcap_index=None):
		if dataset_index == None:
			print("Dataset unspecified when calling predict()")
			return

		#if predicting from a dataset
		if dataset_index!=None:

			packets = self.data_handler.get_packet_information(dataset_index, pcap_index)
			labels = self.data_handler.get_labels(dataset_index, pcap_index)

			#turns each packet data from dictionaries into a flat 1d list. 
			compressed_packets = self.data_handler.compress_packets(packets)


			input_data = self.data_handler.generate_input_data(compressed_packets)

			normalized_input, normalized_output = self.data_handler.normalize_compressed_packets(input_data, labels, dataset_index)

			print("Num packets: "+str(len(normalized_input)))
			print("Num labels: "+str(len(normalized_output)))


			#feeds input data and output data into the neural network
			predicted_labels = self.neural_network.predict(normalized_input)

			# self.data_handler.save_prediction(dataset_index, pcap_index)


	#predicting live pcap files
	def predict_live(self, dataset_index=None):
		if dataset_index == None:
			print("Dataset unspecified when calling predict()")
			return
	
		interface = input("Enter interface name: ")
		if not os.path.isdir("./Live"):
			os.mkdir("./Live")
		while True:
			TIME_BATCH_SIZE = input("Enter time batch size (seconds): ")
			try:
				TIME_BATCH_SIZE = int(TIME_BATCH_SIZE)
				break
			except ValueError:
				print("Invalid time batch size")
		capture_thread = threading.Thread(target=self.capture_live_traffic, args=(interface,))
		capture_thread.start()
		self.stats_file.write("pps,time to predict\n")
		try:
			while True:
				time.sleep(TIME_BATCH_SIZE)
				latest_pcap_path = self.save_live_packets_to_pcap()

				if latest_pcap_path=="":
					print("There is no pcap file to predict from")
					return

				print("Latest pcap path: "+str(latest_pcap_path))

				#returns normalized input data from the specified pcap path
				normalized_input = self.data_handler.get_live_input_data(latest_pcap_path)

				if (normalized_input is None):
					print("Num packets: 0")
					print("pps : 0")
					self.stats_file.write(f"0,0\n")
				else:
					print("Num packets: "+str(len(normalized_input)))

					latest_packet = [normalized_input[-1]]

					#feeds input data and output data into the neural network
					
					predicted_label = self.neural_network.predict(dataset_index, normalized_input, callbacks=[self.perf])
		
					time_elapsed_predict = self.perf.total_time
					pps = len(normalized_input)/TIME_BATCH_SIZE
					print("pps : "+str(pps))
					print("--- %s ms to predict ---" % (time_elapsed_predict/1000000))
					self.stats_file.write(f"{str(pps)},{time_elapsed_predict/1000000}\n")
					if len(predicted_label) > 0:
						predicted_label = predicted_label[-1][0]

						print("Predicted label: "+str(predicted_label))
					else:
						print("No predictions for live data")
				os.remove(latest_pcap_path)
				print()
		except KeyboardInterrupt:
			print("Arret de la capture...")
			self.stats_file.close()
			self.stop_capture_thread.set()


	def capture_live_traffic(self, interface):
			asyncio.set_event_loop(asyncio.new_event_loop())
			if not self.must_clear:
				sniff(prn=lambda x: self.captured_packets.append(x), iface=interface, stop_filter=lambda x: self.stop_capture_thread.is_set())


	def save_live_packets_to_pcap(self):
		latest_pcap_path = f"./Live/captured_live_packets_{time.strftime('%Y%m%d%H%M%S')}.pcap"
		self.must_clear = True
		wrpcap(latest_pcap_path, self.captured_packets)
		print(f"Packets saved in {latest_pcap_path}")

		# Supprimez les paquets après les avoir enregistrés
		self.captured_packets.clear()
		self.must_clear = False

		return latest_pcap_path



if __name__=="__main__":

	DDoS_detector = DDoSDetector()


	DDoS_detector.train(dataset_index=1, pcap_index=None)

	# DDoS_detector.predict()

	