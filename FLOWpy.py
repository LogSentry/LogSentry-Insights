import scapy.all as scapy
import pandas as pd
import numpy as np
from datetime import datetime
import sys
import logging
import concurrent.futures
from collections import defaultdict
from threading import Lock

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Define TCP flag constants if they are not available in scapy
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

# Use a lock to ensure thread-safe access to shared resources
lock = Lock()

def process_packet(packet, flows, flow_keys):
    if packet.haslayer(scapy.IP):
        ip = packet.getlayer(scapy.IP)
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        src_port = dst_port = 0
        
        if packet.haslayer(scapy.TCP):
            tcp = packet.getlayer(scapy.TCP)
            src_port = tcp.sport
            dst_port = tcp.dport
        elif packet.haslayer(scapy.UDP):
            udp = packet.getlayer(scapy.UDP)
            src_port = udp.sport
            dst_port = udp.dport

        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        with lock:
            if key not in flow_keys:
                flow_keys.add(key)
                flows[key] = {
                    'packet_count': 0,
                    'byte_count': 0,
                    'fwd_packet_count': 0,
                    'bwd_packet_count': 0,
                    'fwd_byte_count': 0,
                    'bwd_byte_count': 0,
                    'fwd_packet_length_min': float('inf'),
                    'fwd_packet_length_max': 0,
                    'bwd_packet_length_min': float('inf'),
                    'bwd_packet_length_max': 0,
                    'flow_bytes_per_sec': 0,
                    'flow_packets_per_sec': 0,
                    'flow_iat_mean': 0,
                    'flow_iat_std': 0,
                    'flow_iat_max': 0,
                    'flow_iat_min': float('inf'),
                    'fwd_psh_flags': 0,
                    'bwd_psh_flags': 0,
                    'fwd_urg_flags': 0,
                    'bwd_urg_flags': 0,
                    'fwd_header_length': 0,
                    'bwd_header_length': 0,
                    'fin_flag_count': 0,
                    'syn_flag_count': 0,
                    'rst_flag_count': 0,
                    'psh_flag_count': 0,
                    'ack_flag_count': 0,
                    'urg_flag_count': 0,
                    'down_up_ratio': 0,
                    'avg_packet_size': 0,
                    'avg_fwd_segment_size': 0,
                    'avg_bwd_segment_size': 0,
                    'subflow_fwd_packets': 0,
                    'subflow_fwd_bytes': 0,
                    'subflow_bwd_packets': 0,
                    'subflow_bwd_bytes': 0,
                    'init_win_bytes_forward': 0,
                    'init_win_bytes_backward': 0,
                    'active_mean': 0,
                    'idle_mean': 0,
                    'start_time': packet.time,
                    'last_time': packet.time,
                    'fwd_packet_length_sum': 0,
                    'bwd_packet_length_sum': 0,
                    'fwd_packet_count': 0,
                    'bwd_packet_count': 0
                }
                logging.debug(f"New flow added: {key}")

            flow = flows[key]
            flow['packet_count'] += 1
            flow['byte_count'] += len(packet)

            current_time = packet.time
            if flow['packet_count'] > 1:
                iat = current_time - flow['last_time']
                flow['flow_iat_mean'] = (flow['flow_iat_mean'] * (flow['packet_count'] - 2) + iat) / (flow['packet_count'] - 1)
                flow['flow_iat_std'] = np.sqrt(
                    (flow['flow_iat_std']**2 * (flow['packet_count'] - 2) + (iat - flow['flow_iat_mean'])**2) / (flow['packet_count'] - 1)
                )
                flow['flow_iat_max'] = max(iat, flow['flow_iat_max'])
                flow['flow_iat_min'] = min(iat, flow['flow_iat_min'])
            flow['last_time'] = current_time

            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                flow['fwd_packet_count'] += 1
                flow['fwd_byte_count'] += len(packet)
                flow['fwd_packet_length_min'] = min(flow['fwd_packet_length_min'], len(packet))
                flow['fwd_packet_length_max'] = max(flow['fwd_packet_length_max'], len(packet))
                flow['fwd_packet_length_sum'] += len(packet)
            else:
                flow['bwd_packet_count'] += 1
                flow['bwd_byte_count'] += len(packet)
                flow['bwd_packet_length_min'] = min(flow['bwd_packet_length_min'], len(packet))
                flow['bwd_packet_length_max'] = max(flow['bwd_packet_length_max'], len(packet))
                flow['bwd_packet_length_sum'] += len(packet)

            if packet.haslayer(scapy.TCP):
                tcp = packet.getlayer(scapy.TCP)
                flow['fwd_psh_flags'] += (tcp.flags & PSH) >> 3
                flow['bwd_psh_flags'] += (tcp.flags & PSH) >> 3
                flow['fwd_urg_flags'] += (tcp.flags & URG) >> 5
                flow['bwd_urg_flags'] += (tcp.flags & URG) >> 5
                flow['fin_flag_count'] += (tcp.flags & FIN) >> 0
                flow['syn_flag_count'] += (tcp.flags & SYN) >> 1
                flow['rst_flag_count'] += (tcp.flags & RST) >> 2
                flow['psh_flag_count'] += (tcp.flags & PSH) >> 3
                flow['ack_flag_count'] += (tcp.flags & ACK) >> 4
                flow['urg_flag_count'] += (tcp.flags & URG) >> 5

            logging.debug(f"Updated flow: {key} with packet length {len(packet)}")

def pcap_to_csv(pcap_file, csv_file):
    pcap = scapy.rdpcap(pcap_file)
    flows = {}
    flow_keys = set()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit packets to the executor
        future_to_packet = {executor.submit(process_packet, packet, flows, flow_keys): packet for packet in pcap}
        
        # Wait for all packets to be processed
        for future in concurrent.futures.as_completed(future_to_packet):
            try:
                future.result()  # This will re-raise any exceptions that occurred during processing
            except Exception as e:
                logging.error(f"Packet processing generated an exception: {e}")

    # Convert flows to DataFrame
    data = []
    for key, flow in flows.items():
        src_ip, dst_ip, src_port, dst_port, protocol = key
        # Ensure that we have a valid start and end time
        duration = (flow['last_time'] - flow['start_time']) if (flow['last_time'] - flow['start_time']) > 0 else 1
        data.append({
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Source Port': src_port,
            'Destination Port': dst_port,
            'Protocol': protocol,
            'Packet Count': flow['packet_count'],
            'Byte Count': flow['byte_count'],
            'Forward Packet Count': flow['fwd_packet_count'],
            'Backward Packet Count': flow['bwd_packet_count'],
            'Forward Byte Count': flow['fwd_byte_count'],
            'Backward Byte Count': flow['bwd_byte_count'],
            'Forward Packet Length Min': flow['fwd_packet_length_min'],
            'Forward Packet Length Max': flow['fwd_packet_length_max'],
            'Backward Packet Length Min': flow['bwd_packet_length_min'],
            'Backward Packet Length Max': flow['bwd_packet_length_max'],
            'Forward Packet Length Mean': flow['fwd_packet_length_sum'] / (flow['fwd_packet_count'] if flow['fwd_packet_count'] > 0 else 1),
            'Backward Packet Length Mean': flow['bwd_packet_length_sum'] / (flow['bwd_packet_count'] if flow['bwd_packet_count'] > 0 else 1),
            'Flow Bytes Per Sec': flow['byte_count'] / duration,
                        'Flow Packets Per Sec': flow['packet_count'] / duration,
            'Flow IAT Mean': flow['flow_iat_mean'],
            'Flow IAT Std': flow['flow_iat_std'],
            'Flow IAT Max': flow['flow_iat_max'],
            'Flow IAT Min': flow['flow_iat_min'],
            'Forward PSH Flags': flow['fwd_psh_flags'],
            'Backward PSH Flags': flow['bwd_psh_flags'],
            'Forward URG Flags': flow['fwd_urg_flags'],
            'Backward URG Flags': flow['bwd_urg_flags'],
            'Forward Header Length': flow['fwd_header_length'],
            'Backward Header Length': flow['bwd_header_length'],
            'FIN Flag Count': flow['fin_flag_count'],
            'SYN Flag Count': flow['syn_flag_count'],
            'RST Flag Count': flow['rst_flag_count'],
            'PSH Flag Count': flow['psh_flag_count'],
            'ACK Flag Count': flow['ack_flag_count'],
            'URG Flag Count': flow['urg_flag_count'],
            'Down Up Ratio': flow['down_up_ratio'],
            'Average Packet Size': flow['avg_packet_size'],
            'Average Forward Segment Size': flow['avg_fwd_segment_size'],
            'Average Backward Segment Size': flow['avg_bwd_segment_size'],
            'Subflow Forward Packets': flow['subflow_fwd_packets'],
            'Subflow Forward Bytes': flow['subflow_fwd_bytes'],
            'Subflow Backward Packets': flow['subflow_bwd_packets'],
            'Subflow Backward Bytes': flow['subflow_bwd_bytes'],
            'Init Win Bytes Forward': flow['init_win_bytes_forward'],
            'Init Win Bytes Backward': flow['init_win_bytes_backward'],
            'Active Mean': flow['active_mean'],
            'Idle Mean': flow['idle_mean']
        })

    df = pd.DataFrame(data)
    df.to_csv(csv_file, index=False)
    logging.debug(f"CSV file created: {csv_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_pcap> <output_csv>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    csv_file = sys.argv[2]
    pcap_to_csv(pcap_file, csv_file)

