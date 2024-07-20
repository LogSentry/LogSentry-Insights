import argparse
import csv
import os
import numpy as np
import threading
import tarfile
from scapy.all import rdpcap, IP, TCP, UDP
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil

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

# Check for CUDA and CuPy availability
def check_cuda():
    try:
        import cupy as cp
        import GPUtil
        CUDA_AVAILABLE = len(GPUtil.getGPUs()) > 0
        return True
    except ImportError:
        CUDA_AVAILABLE = False
        return False
    
    
def process_pcap(pcap_file, output_csv, use_cuda=False):
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
                flow['average_packet_size'] = (flow['byte_count'] / flow['packet_count']) if flow['packet_count'] > 0 else 0
                flow['average_forward_segment_size'] = (flow['forward_byte_count'] / flow['forward_packet_count']) if flow['forward_packet_count'] > 0 else 0
                flow['average_backward_segment_size'] = (flow['backward_byte_count'] / flow['backward_packet_count']) if flow['backward_packet_count'] > 0 else 0
                flow['down_up_ratio'] = (flow['forward_packet_count'] / flow['backward_packet_count']) if flow['backward_packet_count'] > 0 else 0
                flow['subflow_forward_packets'] = flow['forward_packet_count']
                flow['subflow_forward_bytes'] = flow['forward_byte_count']
                flow['subflow_backward_packets'] = flow['backward_packet_count']
                flow['subflow_backward_bytes'] = flow['backward_byte_count']
                flow['init_win_bytes_forward'] = 0  # Placeholder
                flow['init_win_bytes_backward'] = 0  # Placeholder
                flow['active_mean'] = flow['active_time'] / flow['active_count'] if flow['active_count'] > 0 else 0
                flow['idle_mean'] = flow['idle_time'] / flow['idle_count'] if flow['idle_count'] > 0 else 0
                
            writer.writerow({field: flow.get(field, 0) for field in fieldnames})

def process_tarfile(tar_file, output_dir, use_cuda=False):
    with tarfile.open(tar_file, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('.pcap'):
                member_file = tar.extractfile(member)
                pcap_file = os.path.join(output_dir, os.path.basename(member.name))
                with open(pcap_file, 'wb') as f:
                    f.write(member_file.read())
                process_pcap(pcap_file, pcap_file.replace('.pcap', '.csv'), use_cuda)

def process_files(input_dir, output_dir, use_cuda=False, recursive=False):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    if recursive:
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.endswith('.pcap'):
                    process_pcap(os.path.join(root, file), os.path.join(output_dir, file.replace('.pcap', '.csv')), use_cuda)
                elif file.endswith('.tar.gz'):
                    process_tarfile(os.path.join(root, file), output_dir, use_cuda)
    else:
        for file in os.listdir(input_dir):
            if file.endswith('.pcap'):
                process_pcap(os.path.join(input_dir, file), os.path.join(output_dir, file.replace('.pcap', '.csv')), use_cuda)
            elif file.endswith('.tar.gz'):
                process_tarfile(os.path.join(input_dir, file), output_dir, use_cuda)

def get_files_size(path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            total_size += os.path.getsize(filepath)
    return total_size

def main():
    parser = argparse.ArgumentParser(description='Process PCAP files and extract network traffic features.')
    parser.add_argument('-i', '--input', required=True, help='Input directory containing PCAP files or TAR.GZ files')
    parser.add_argument('-o', '--output', required=True, help='Output directory for CSV files')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively process files in subdirectories')
    parser.add_argument('-d', '--directory', action='store_true', help='Process directory of .pcap files')
    parser.add_argument('-t', '--tar', action='store_true', help='Process .tar.gz files')
    
    args = parser.parse_args()
    
    use_cuda = check_cuda()
    input_dir = args.input
    output_dir = args.output
    
    # Check if the input directory contains large files that may not fit into RAM
    total_size = get_files_size(input_dir)
    if total_size > 25 * 1024 * 1024 * 1024:  # Files larger than 25GB
        # Dynamic chunk processing can be implemented here if needed
        print("Files are larger than 25GB. Consider implementing dynamic chunk processing.")
    
    process_files(input_dir, output_dir, use_cuda, args.recursive or args.directory)

if __name__ == "__main__":
    main()
