import argparse
import csv
import os
import threading
import tarfile
from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define the fieldnames for the CSV file
fieldnames = [
    'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol',
    'packet_count', 'byte_count', 'forward_packet_count', 'backward_packet_count',
    'forward_byte_count', 'backward_byte_count', 'forward_packet_length_min',
    'forward_packet_length_max', 'backward_packet_length_min', 'backward_packet_length_max',
    'forward_packet_length_mean', 'backward_packet_length_mean', 'flow_bytes_per_sec',
    'flow_packets_per_sec', 'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'forward_psh_flags', 'backward_psh_flags', 'forward_urg_flags', 'backward_urg_flags',
    'forward_header_length', 'backward_header_length', 'fin_flag_count', 'syn_flag_count',
    'rst_flag_count', 'psh_flag_count', 'ack_flag_count', 'urg_flag_count', 'down_up_ratio',
    'average_packet_size', 'average_forward_segment_size', 'average_backward_segment_size',
    'subflow_forward_packets', 'subflow_forward_bytes', 'subflow_backward_packets',
    'subflow_backward_bytes', 'init_win_bytes_forward', 'init_win_bytes_backward',
    'active_mean', 'idle_mean'
]

def process_pcap(pcap_file, output_csv):
    flows = {}
    
    packets = rdpcap(pcap_file)
    for packet in packets:
        if IP in packet and (TCP in packet or UDP in packet):
            ip = packet[IP]
            transport = packet[TCP] if TCP in packet else packet[UDP]
            
            key = (ip.src, ip.dst, transport.sport, transport.dport, ip.proto)
            if key not in flows:
                flows[key] = {
                    'source_ip': ip.src,
                    'destination_ip': ip.dst,
                    'source_port': transport.sport,
                    'destination_port': transport.dport,
                    'protocol': ip.proto,
                    'packet_count': 0,
                    'byte_count': 0,
                    'forward_packet_count': 0,
                    'backward_packet_count': 0,
                    'forward_byte_count': 0,
                    'backward_byte_count': 0,
                    'forward_packet_length_min': float('inf'),
                    'forward_packet_length_max': 0,
                    'backward_packet_length_min': float('inf'),
                    'backward_packet_length_max': 0,
                    'forward_packet_length_sum': 0,
                    'backward_packet_length_sum': 0,
                    'forward_packet_length_mean': 0,
                    'backward_packet_length_mean': 0,
                    'flow_bytes_per_sec': 0,
                    'flow_packets_per_sec': 0,
                    'flow_iat_mean': 0,
                    'flow_iat_std': 0,
                    'flow_iat_max': 0,
                    'flow_iat_min': float('inf'),
                    'forward_psh_flags': 0,
                    'backward_psh_flags': 0,
                    'forward_urg_flags': 0,
                    'backward_urg_flags': 0,
                    'forward_header_length': 0,
                    'backward_header_length': 0,
                    'fin_flag_count': 0,
                    'syn_flag_count': 0,
                    'rst_flag_count': 0,
                    'psh_flag_count': 0,
                    'ack_flag_count': 0,
                    'urg_flag_count': 0,
                    'down_up_ratio': 0,
                    'average_packet_size': 0,
                    'average_forward_segment_size': 0,
                    'average_backward_segment_size': 0,
                    'subflow_forward_packets': 0,
                    'subflow_forward_bytes': 0,
                    'subflow_backward_packets': 0,
                    'subflow_backward_bytes': 0,
                    'init_win_bytes_forward': 0,
                    'init_win_bytes_backward': 0,
                    'active_mean': 0,
                    'idle_mean': 0,
                    'forward_iat_total': 0,
                    'backward_iat_total': 0,
                    'forward_iat_count': 0,
                    'backward_iat_count': 0,
                    'start_time': packet.time,
                    'last_time': packet.time,
                    'active_time': 0,
                    'idle_count': 0,
                    'idle_time': 0,
                    'active_start': None,
                    'idle_start': None,
                    'active_count': 0,
                    'backward_iat_mean': 0
                }

            flow = flows[key]
            flow['packet_count'] += 1
            flow['byte_count'] += len(packet)
            
            is_forward = (ip.src < ip.dst) or (ip.src == ip.dst and transport.sport < transport.dport)
            
            if is_forward:
                flow['forward_packet_count'] += 1
                flow['forward_byte_count'] += len(packet)
                flow['forward_packet_length_min'] = min(flow['forward_packet_length_min'], len(packet))
                flow['forward_packet_length_max'] = max(flow['forward_packet_length_max'], len(packet))
                flow['forward_packet_length_sum'] += len(packet)
                flow['forward_header_length'] += len(ip) + len(transport)
                if flow['forward_packet_count'] > 1:
                    iat = packet.time - flow['last_time']
                    flow['forward_iat_total'] += iat
                    flow['forward_iat_count'] += 1
                    flow['flow_iat_min'] = min(flow['flow_iat_min'], iat)
                    flow['flow_iat_max'] = max(flow['flow_iat_max'], iat)
                if flow['active_start'] is None:
                    flow['active_start'] = packet.time
                flow['idle_start'] = None
            else:
                flow['backward_packet_count'] += 1
                flow['backward_byte_count'] += len(packet)
                flow['backward_packet_length_min'] = min(flow['backward_packet_length_min'], len(packet))
                flow['backward_packet_length_max'] = max(flow['backward_packet_length_max'], len(packet))
                flow['backward_packet_length_sum'] += len(packet)
                flow['backward_header_length'] += len(ip) + len(transport)
                if flow['backward_packet_count'] > 1:
                    iat = packet.time - flow['last_time']
                    flow['backward_iat_total'] += iat
                    flow['backward_iat_count'] += 1
                    flow['flow_iat_min'] = min(flow['flow_iat_min'], iat)
                    flow['flow_iat_max'] = max(flow['flow_iat_max'], iat)
                if flow['idle_start'] is None:
                    flow['idle_start'] = packet.time
                flow['active_start'] = None

            if TCP in packet:
                tcp = packet[TCP]
                flow['fin_flag_count'] += 1 if tcp.flags.F else 0
                flow['syn_flag_count'] += 1 if tcp.flags.S else 0
                flow['rst_flag_count'] += 1 if tcp.flags.R else 0
                flow['psh_flag_count'] += 1 if tcp.flags.P else 0
                flow['ack_flag_count'] += 1 if tcp.flags.A else 0
                flow['urg_flag_count'] += 1 if tcp.flags.U else 0

            flow['last_time'] = packet.time

    # Calculate additional statistics and write to CSV
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for flow in flows.values():
            if flow['packet_count'] > 0:
                flow['duration'] = flow['last_time'] - flow['start_time']
                flow['flow_bytes_per_sec'] = flow['byte_count'] / flow['duration'] if flow['duration'] > 0 else 0
                flow['flow_packets_per_sec'] = flow['packet_count'] / flow['duration'] if flow['duration'] > 0 else 0
                flow['forward_packet_length_mean'] = (flow['forward_packet_length_sum'] / flow['forward_packet_count']) if flow['forward_packet_count'] > 0 else 0
                flow['backward_packet_length_mean'] = (flow['backward_packet_length_sum'] / flow['backward_packet_count']) if flow['backward_packet_count'] > 0 else 0
                flow['flow_iat_mean'] = ((flow['forward_iat_total'] + flow['backward_iat_total']) / (flow['forward_iat_count'] + flow['backward_iat_count'])) if (flow['forward_iat_count'] + flow['backward_iat_count']) > 0 else 0
                flow['flow_iat_std'] = np.std([packet.time - flow['start_time'] for packet in packets]) if len(packets) > 0 else 0
                flow['down_up_ratio'] = flow['forward_byte_count'] / (flow['backward_byte_count'] if flow['backward_byte_count'] > 0 else 1)  # Avoid division by zero
                flow['average_packet_size'] = flow['byte_count'] / flow['packet_count'] if flow['packet_count'] > 0 else 0

                # Add any additional calculations as needed

                writer.writerow({
                    'source_ip': flow['source_ip'],
                    'destination_ip': flow['destination_ip'],
                    'source_port': flow['source_port'],
                    'destination_port': flow['destination_port'],
                    'protocol': flow['protocol'],
                    'packet_count': flow['packet_count'],
                    'byte_count': flow['byte_count'],
                    'forward_packet_count': flow['forward_packet_count'],
                    'backward_packet_count': flow['backward_packet_count'],
                    'forward_byte_count': flow['forward_byte_count'],
                    'backward_byte_count': flow['backward_byte_count'],
                    'forward_packet_length_min': flow['forward_packet_length_min'],
                    'forward_packet_length_max': flow['forward_packet_length_max'],
                    'backward_packet_length_min': flow['backward_packet_length_min'],
                    'backward_packet_length_max': flow['backward_packet_length_max'],
                    'forward_packet_length_mean': flow['forward_packet_length_mean'],
                    'backward_packet_length_mean': flow['backward_packet_length_mean'],
                    'flow_bytes_per_sec': flow['flow_bytes_per_sec'],
                    'flow_packets_per_sec': flow['flow_packets_per_sec'],
                    'flow_iat_mean': flow['flow_iat_mean'],
                    'flow_iat_std': flow['flow_iat_std'],
                    'flow_iat_max': flow['flow_iat_max'],
                    'flow_iat_min': flow['flow_iat_min'],
                    'forward_psh_flags': flow['forward_psh_flags'],
                    'backward_psh_flags': flow['backward_psh_flags'],
                    'forward_urg_flags': flow['forward_urg_flags'],
                    'backward_urg_flags': flow['backward_urg_flags'],
                    'forward_header_length': flow['forward_header_length'],
                    'backward_header_length': flow['backward_header_length'],
                    'fin_flag_count': flow['fin_flag_count'],
                    'syn_flag_count': flow['syn_flag_count'],
                    'rst_flag_count': flow['rst_flag_count'],
                    'psh_flag_count': flow['psh_flag_count'],
                    'ack_flag_count': flow['ack_flag_count'],
                    'urg_flag_count': flow['urg_flag_count'],
                    'down_up_ratio': flow['down_up_ratio'],
                    'average_packet_size': flow['average_packet_size'],
                    'average_forward_segment_size': flow['average_forward_segment_size'],
                    'average_backward_segment_size': flow['average_backward_segment_size'],
                    'subflow_forward_packets': flow['subflow_forward_packets'],
                    'subflow_forward_bytes': flow['subflow_forward_bytes'],
                    'subflow_backward_packets': flow['subflow_backward_packets'],
                    'subflow_backward_bytes': flow['subflow_backward_bytes'],
                    'init_win_bytes_forward': flow['init_win_bytes_forward'],
                    'init_win_bytes_backward': flow['init_win_bytes_backward'],
                    'active_mean': flow['active_mean'],
                    'idle_mean': flow['idle_mean']
                })

def process_directory(input_dir, output_dir, max_threads):
    # Get list of all .pcap files in the input directory
    pcap_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith('.pcap')]
    total_files = len(pcap_files)
    print(f"Found {total_files} .pcap files in directory {input_dir}")

    def process_file(pcap_file):
        output_csv = os.path.join(output_dir, os.path.basename(pcap_file) + '.csv')
        print(f"Processing {pcap_file}...")
        process_pcap(pcap_file, output_csv)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(process_file, pcap_file) for pcap_file in pcap_files]
        for future in as_completed(futures):
            try:
                future.result()  # Retrieve result or raise exception if any
            except Exception as e:
                print(f"Error processing file: {e}")

def main():
    parser = argparse.ArgumentParser(description='Process .pcap files into CSV format.')
    parser.add_argument('-i', '--input', required=True, help='Input directory containing .pcap files')
    parser.add_argument('-o', '--output', required=True, help='Output directory for CSV files')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    # Determine the number of threads to use
    max_threads = int(os.cpu_count() * 0.75)  # Use 75% of available CPU threads

    if args.debug:
        print(f"Debug mode enabled")
        print(f"Input directory: {args.input}")
        print(f"Output directory: {args.output}")
        print(f"Max threads: {max_threads}")

    if not os.path.exists(args.input):
        raise FileNotFoundError(f"Input directory {args.input} does not exist")
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    process_directory(args.input, args.output, max_threads)

if __name__ == '__main__':
    main()

