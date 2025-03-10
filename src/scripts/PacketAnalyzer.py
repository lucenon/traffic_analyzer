from scapy.layers.inet import IP
from scapy.utils import checksum
from src.scripts import predict, config
import numpy as np
import csv
import signal
from datetime import datetime


class PacketAnalyzer:
    def __init__(self, mode, model, duration=10, file_path=None, file_record_path=config.FILE_RECORD):
        self.__duration = duration
        self.mode = mode
        self.file_path = file_path
        self.file_record_path = file_record_path
        self.model = model
        self.running = True

        self.file = open(self.file_record_path, 'a', newline='')
        self.writer = csv.writer(self.file)

        signal.signal(signal.SIGINT, self.stop)

    def __del__(self):
        self.file.close()

    @property
    def duration(self):
        return self.__duration

    @duration.setter
    def duration(self, duration):
        if duration > 0:
            self.__duration = duration
        else:
            self.__duration = config.DURATION

    def analyze(self, packets):
        print(f"Received {len(packets)} packets. Processing...")
        total_length = count_ICMP = count_ARP = attention_ports = count_SYN = count_ACK = count_RST = error_rcode = 0
        min_ttl = float('inf')
        max_ttl = float('-inf')
        unique_macs_dst = set()
        unique_ips_src = set()
        unique_ips_dst = set()
        unique_dest_ports = set()

        if packets:
            packets.sort(key=lambda x: x.time)
            packet_count = len(packets)

            for packet in packets:
                total_length += len(packet.payload)

                if packet.haslayer('ICMP'):
                    count_ICMP += 1

                if packet.haslayer('ARP'):
                    count_ARP += 1

                if packet.haslayer('Ether'):
                    unique_macs_dst.add(packet['Ether'].dst)

                if packet.haslayer(IP):
                    unique_ips_src.add(packet['IP'].src)
                    unique_ips_dst.add(packet['IP'].dst)
                    min_ttl = min(min_ttl, packet[IP].ttl)
                    max_ttl = max(max_ttl, packet[IP].ttl)

                if packet.haslayer('TCP'):
                    unique_dest_ports.add(packet.dport)
                    if packet['TCP'].sport in {21, 22, 23, 445, 3389, 5432} or packet['TCP'].dport in {21, 22, 23, 445,
                                                                                                       3389, 5432}:
                        attention_ports += 1

                    if 'S' in packet['TCP'].flags:
                        count_SYN += 1

                    if 'A' in packet['TCP'].flags:
                        count_ACK += 1

                    if 'R' in packet['TCP'].flags:
                        count_RST += 1

                if packet.haslayer('UDP'):
                    unique_dest_ports.add(packet.dport)

                if packet.haslayer('DNS') and packet['DNS'].rcode != 0:
                    error_rcode += 1

            count_checksum = sum(1 for packet in packets if
                                 packet.haslayer(IP) and packet.getlayer(IP).chksum != checksum(
                                     bytes(packet.getlayer(IP))))

            mean_length = total_length / packet_count

            average_time_diff = sum(packets[i].time - packets[i - 1].time for i in range(1, len(packets))) / (
                    len(packets) - 1) if len(packets) > 1 else 0

            data = [str(datetime.now().time()), mean_length, average_time_diff, count_ICMP, count_ARP,
                    len(unique_dest_ports), attention_ports, len(unique_ips_src.union(unique_ips_dst)),
                    len(unique_macs_dst), count_SYN, count_ACK, count_RST, count_checksum, error_rcode, min_ttl,
                    max_ttl]
        else:
            data = [datetime.now().time()] + [0] * 15

        if self.mode:
            result = predict.analyze_data(self.model, np.array(data))
            self.writer.writerow([*data, result])
        else:
            self.writer.writerow([*data])

    def analyze_file(self, file_path):
        try:
            packets = rdpcap(file_path)
            start_time = packets[0].time
            time_intervals = [start_time + i * 10 for i in range(int((packets[-1].time - start_time) // 10) + 1)]

            for i in range(len(time_intervals) - 1):
                interval_packets = [packet for packet in packets if
                                    time_intervals[i] <= packet.time < time_intervals[i + 1]]
                if interval_packets:
                    self.analyze(interval_packets)
        except FileNotFoundError:
            print(f"File not found: {file_path}")

    def stop(self, signum, frame):
        print("Stopping packet capture...")
        self.running = False

    def capture(self, duration):
        while self.running:
            print(f"Capturing packets for the next {duration} seconds...")
            packets = sniff(timeout=duration)
            self.analyze(packets)
