import argparse
import csv
import os
import numpy as np
import tarfile
from scapy.all import rdpcap, IP, TCP, UDP
from scapy.layers.http import HTTP
import concurrent.futures
import psutil
import math
from decimal import Decimal
import logging
import multiprocessing as mp
from tqdm import tqdm
import sys
import glob
import time
import ast

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Define the all_fieldnames for the CSV file
all_fieldnames = [
    'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol',
    'flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot', 'fwd_data_pkts_tot', 'bwd_data_pkts_tot',
    'fwd_pkts_per_sec', 'bwd_pkts_per_sec', 'flow_pkts_per_sec', 'down_up_ratio',
    'fwd_header_size_tot', 'fwd_header_size_min', 'fwd_header_size_max',
    'bwd_header_size_tot', 'bwd_header_size_min', 'bwd_header_size_max',
    'fwd_pkts_payload_max', 'fwd_pkts_payload_min', 'fwd_pkts_payload_tot', 'fwd_pkts_payload_avg', 'fwd_pkts_payload_std',
    'bwd_pkts_payload_max', 'bwd_pkts_payload_min', 'bwd_pkts_payload_tot', 'bwd_pkts_payload_avg', 'bwd_pkts_payload_std',
    'flow_pkts_payload_max', 'flow_pkts_payload_min', 'flow_pkts_payload_tot', 'flow_pkts_payload_avg', 'flow_pkts_payload_std',
    'payload_bytes_per_second', 'flow_FIN_flag_count', 'flow_SYN_flag_count', 'flow_RST_flag_count',
    'fwd_PSH_flag_count', 'bwd_PSH_flag_count', 'flow_ACK_flag_count',
    'fwd_URG_flag_count', 'bwd_URG_flag_count', 'flow_CWR_flag_count', 'flow_ECE_flag_count',
    'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_tot', 'fwd_iat_avg', 'fwd_iat_std',
    'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_tot', 'bwd_iat_avg', 'bwd_iat_std',
    'flow_iat_max', 'flow_iat_min', 'flow_iat_tot', 'flow_iat_avg', 'flow_iat_std',
    'fwd_subflow_pkts', 'bwd_subflow_pkts', 'fwd_subflow_bytes', 'bwd_subflow_bytes',
    'fwd_bulk_bytes', 'bwd_bulk_bytes', 'fwd_bulk_packets', 'bwd_bulk_packets',
    'fwd_bulk_rate', 'bwd_bulk_rate',
    'active_max', 'active_min', 'active_tot', 'active_avg', 'active_std',
    'idle_max', 'idle_min', 'idle_tot', 'idle_avg', 'idle_std',
    'fwd_init_window_size', 'bwd_init_window_size', 'fwd_last_window_size', 'bwd_last_window_size',
    'average_packet_size', 'start_time', 'last_time', 'fwd_pkts_payload'
]

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Process PCAP files to extract flow metrics.")
parser.add_argument("-i", "--input", required=True, help="Input PCAP file or directory.")
parser.add_argument("-o", "--output", required=True, help="Output directory for CSV files.")
parser.add_argument("-p", "--parameters", required=True, help="Parameters to calculate. Format: \"param1\" or [\"param1\", \"param2\", ...]")
parser.add_argument("-t", "--tar", action="store_true", help="Enable processing of tar and tar.gz files.")



# Update all_fieldnames based on user input
all_fieldnames = parser.parameters

def process_pcap_chunk(packets):
    flow_stats = {}
    for packet in packets:
        if IP in packet and (TCP in packet or UDP):
            ip = packet[IP]
            transport = packet[TCP] if TCP in packet else packet[UDP]
            
            key = (ip.src, ip.dst, transport.sport, transport.dport, ip.proto)
            if key not in flow_stats:
                flow_stats[key] = {
                    'source_ip': ip.src,
                    'destination_ip': ip.dst,
                    'source_port': transport.sport,
                    'destination_port': transport.dport,
                    'protocol': ip.proto,
                    'start_time': packet.time,
                    'last_time': packet.time,
                    'fwd_pkts_tot': 0,
                    'bwd_pkts_tot': 0,
                    'fwd_data_pkts_tot': 0,
                    'bwd_data_pkts_tot': 0,
                    'fwd_pkts_payload': [],
                    'bwd_pkts_payload': [],
                    'fwd_header_size_tot': 0,
                    'bwd_header_size_tot': 0,
                    'fwd_iat': [],
                    'bwd_iat': [],
                    'active_times': [],
                    'idle_times': [],
                    'flow_FIN_flag_count': 0,
                    'flow_SYN_flag_count': 0,
                    'flow_RST_flag_count': 0,
                    'fwd_PSH_flag_count': 0,
                    'bwd_PSH_flag_count': 0,
                    'flow_ACK_flag_count': 0,
                    'fwd_URG_flag_count': 0,
                    'bwd_URG_flag_count': 0,
                    'flow_CWR_flag_count': 0,
                    'flow_ECE_flag_count': 0,
                    'fwd_window_sizes': [],
                    'bwd_window_sizes': [],
                }

            flow = flow_stats[key]
            is_forward = (ip.src < ip.dst) or (ip.src == ip.dst and transport.sport < transport.dport)
            
            # Update packet counts and bytes
            flow['fwd_pkts_tot' if is_forward else 'bwd_pkts_tot'] += 1
            flow['fwd_data_pkts_tot' if is_forward else 'bwd_data_pkts_tot'] += 1 if len(packet.payload) > 0 else 0
            
            payload_size = len(packet.payload)
            if is_forward:
                flow['fwd_pkts_payload'].append(payload_size)
                flow['fwd_header_size_tot'] += len(ip) + len(transport)
                if flow['fwd_pkts_tot'] > 1:
                    flow['fwd_iat'].append(packet.time - flow['last_time'])
            else:
                flow['bwd_pkts_payload'].append(payload_size)
                flow['bwd_header_size_tot'] += len(ip) + len(transport)
                if flow['bwd_pkts_tot'] > 1:
                    flow['bwd_iat'].append(packet.time - flow['last_time'])
            
            # Update TCP flags
            if TCP in packet:
                tcp = packet[TCP]
                flow['flow_FIN_flag_count'] += 1 if tcp.flags.F else 0
                flow['flow_SYN_flag_count'] += 1 if tcp.flags.S else 0
                flow['flow_RST_flag_count'] += 1 if tcp.flags.R else 0
                flow['flow_ACK_flag_count'] += 1 if tcp.flags.A else 0
                flow['flow_CWR_flag_count'] += 1 if tcp.flags.C else 0
                flow['flow_ECE_flag_count'] += 1 if tcp.flags.E else 0
                
                if is_forward:
                    flow['fwd_PSH_flag_count'] += 1 if tcp.flags.P else 0
                    flow['fwd_URG_flag_count'] += 1 if tcp.flags.U else 0
                    flow['fwd_window_sizes'].append(tcp.window)
                else:
                    flow['bwd_PSH_flag_count'] += 1 if tcp.flags.P else 0
                    flow['bwd_URG_flag_count'] += 1 if tcp.flags.U else 0
                    flow['bwd_window_sizes'].append(tcp.window)

            # Update active and idle times
            if flow['active_times'] and packet.time - flow['last_time'] > 1:
                flow['idle_times'].append(packet.time - flow['last_time'])
                flow['active_times'].append(0)
            elif flow['active_times']:
                flow['active_times'][-1] += packet.time - flow['last_time']
            else:
                flow['active_times'].append(0)

            flow['last_time'] = packet.time

    return flow_stats
    

# Convert Decimal to float
def to_float(value):
    if isinstance(value, Decimal):
        return float(value)
    return value

# To Prevent Division by Zero
def safe_division(n, d):
    n, d = to_float(n), to_float(d)
    return n / d if d else 0

def calculate_flow_statistics(flow):
    flow['flow_duration'] = to_float(flow['last_time'] - flow['start_time'])
    
    # Calculate packet rates
    flow['fwd_pkts_per_sec'] = safe_division(flow['fwd_pkts_tot'], flow['flow_duration'])
    flow['bwd_pkts_per_sec'] = safe_division(flow['bwd_pkts_tot'], flow['flow_duration'])
    flow['flow_pkts_per_sec'] = flow['fwd_pkts_per_sec'] + flow['bwd_pkts_per_sec']
    
    # Calculate payload statistics
    flow['fwd_pkts_payload_tot'] = sum(flow['fwd_pkts_payload'])
    flow['bwd_pkts_payload_tot'] = sum(flow['bwd_pkts_payload'])
    flow['flow_pkts_payload_tot'] = flow['fwd_pkts_payload_tot'] + flow['bwd_pkts_payload_tot']
    
    flow['fwd_pkts_payload_max'] = max(flow['fwd_pkts_payload'], default=0)
    flow['fwd_pkts_payload_min'] = min(flow['fwd_pkts_payload'], default=0)
    flow['fwd_pkts_payload_avg'] = safe_division(flow['fwd_pkts_payload_tot'], len(flow['fwd_pkts_payload']))
    flow['fwd_pkts_payload_std'] = np.std(flow['fwd_pkts_payload']) if flow['fwd_pkts_payload'] else 0
    
    flow['bwd_pkts_payload_max'] = max(flow['bwd_pkts_payload'], default=0)
    flow['bwd_pkts_payload_min'] = min(flow['bwd_pkts_payload'], default=0)
    flow['bwd_pkts_payload_avg'] = safe_division(flow['bwd_pkts_payload_tot'], len(flow['bwd_pkts_payload']))
    flow['bwd_pkts_payload_std'] = np.std(flow['bwd_pkts_payload']) if flow['bwd_pkts_payload'] else 0
    
    flow['flow_pkts_payload_max'] = max(flow['fwd_pkts_payload_max'], flow['bwd_pkts_payload_max'])
    flow['flow_pkts_payload_min'] = min(flow['fwd_pkts_payload_min'], flow['bwd_pkts_payload_min'])
    flow['flow_pkts_payload_avg'] = safe_division(flow['flow_pkts_payload_tot'], len(flow['fwd_pkts_payload']) + len(flow['bwd_pkts_payload']))
    flow['flow_pkts_payload_std'] = np.std(flow['fwd_pkts_payload'] + flow['bwd_pkts_payload']) if flow['fwd_pkts_payload'] + flow['bwd_pkts_payload'] else 0
    
    flow['payload_bytes_per_second'] = safe_division(flow['flow_pkts_payload_tot'], flow['flow_duration'])
    
    # Calculate header statistics
    flow['fwd_header_size_min'] = safe_division(flow['fwd_header_size_tot'], flow['fwd_pkts_tot'])
    flow['fwd_header_size_max'] = safe_division(flow['fwd_header_size_tot'], flow['fwd_pkts_tot'])
    flow['bwd_header_size_min'] = safe_division(flow['bwd_header_size_tot'], flow['bwd_pkts_tot'])
    flow['bwd_header_size_max'] = safe_division(flow['bwd_header_size_tot'], flow['bwd_pkts_tot'])
    
    # Calculate IAT statistics
    flow['fwd_iat_max'] = max(flow['fwd_iat'], default=0)
    flow['fwd_iat_min'] = min(flow['fwd_iat'], default=0)
    flow['fwd_iat_tot'] = sum(flow['fwd_iat'])
    flow['fwd_iat_avg'] = safe_division(flow['fwd_iat_tot'], len(flow['fwd_iat']))
    flow['fwd_iat_std'] = np.std(flow['fwd_iat']) if flow['fwd_iat'] else 0
    
    flow['bwd_iat_max'] = max(flow['bwd_iat'], default=0)
    flow['bwd_iat_min'] = min(flow['bwd_iat'], default=0)
    flow['bwd_iat_tot'] = sum(flow['bwd_iat'])
    flow['bwd_iat_avg'] = safe_division(flow['bwd_iat_tot'], len(flow['bwd_iat']))
    flow['bwd_iat_std'] = np.std(flow['bwd_iat']) if flow['bwd_iat'] else 0
    
    flow['flow_iat_max'] = max(flow['fwd_iat_max'], flow['bwd_iat_max'])
    flow['flow_iat_min'] = min(flow['fwd_iat_min'], flow['bwd_iat_min'])
    flow['flow_iat_tot'] = flow['fwd_iat_tot'] + flow['bwd_iat_tot']
    flow['flow_iat_avg'] = safe_division(flow['flow_iat_tot'], len(flow['fwd_iat']) + len(flow['bwd_iat']))
    flow['flow_iat_std'] = np.std(flow['fwd_iat'] + flow['bwd_iat']) if flow['fwd_iat'] + flow['bwd_iat'] else 0
    
    # Calculate subflow statistics
    flow['fwd_subflow_pkts'] = len(flow['fwd_pkts_payload'])
    flow['bwd_subflow_pkts'] = len(flow['bwd_pkts_payload'])
    flow['fwd_subflow_bytes'] = flow['fwd_pkts_payload_tot']
    flow['bwd_subflow_bytes'] = flow['bwd_pkts_payload_tot']
    
    # Calculate bulk statistics
    flow['fwd_bulk_bytes'] = sum(1 for size in flow['fwd_pkts_payload'] if size > 0)
    flow['bwd_bulk_bytes'] = sum(1 for size in flow['bwd_pkts_payload'] if size > 0)
    flow['fwd_bulk_packets'] = sum(1 for size in flow['fwd_pkts_payload'] if size > 0)
    flow['bwd_bulk_packets'] = sum(1 for size in flow['bwd_pkts_payload'] if size > 0)
    
    flow['fwd_bulk_rate'] = safe_division(flow['fwd_bulk_bytes'], flow['flow_duration'])
    flow['bwd_bulk_rate'] = safe_division(flow['bwd_bulk_bytes'], flow['flow_duration'])
    
    # Calculate active and idle times
    flow['active_max'] = max(flow['active_times'], default=0)
    flow['active_min'] = min(flow['active_times'], default=0)
    flow['active_tot'] = sum(flow['active_times'])
    flow['active_avg'] = safe_division(flow['active_tot'], len(flow['active_times']))
    flow['active_std'] = np.std(flow['active_times']) if flow['active_times'] else 0
    
    flow['idle_max'] = max(flow['idle_times'], default=0)
    flow['idle_min'] = min(flow['idle_times'], default=0)
    flow['idle_tot'] = sum(flow['idle_times'])
    flow['idle_avg'] = safe_division(flow['idle_tot'], len(flow['idle_times']))
    flow['idle_std'] = np.std(flow['idle_times']) if flow['idle_times'] else 0
    
    # Calculate window sizes
    flow['fwd_init_window_size'] = flow['fwd_window_sizes'][0] if flow['fwd_window_sizes'] else 0
    flow['bwd_init_window_size'] = flow['bwd_window_sizes'][0] if flow['bwd_window_sizes'] else 0
    flow['fwd_last_window_size'] = flow['fwd_window_sizes'][-1] if flow['fwd_window_sizes'] else 0
    flow['bwd_last_window_size'] = flow['bwd_window_sizes'][-1] if flow['bwd_window_sizes'] else 0
    
   
    return flow

def extract_pcap_info(pcap_file):
    try:
        with PcapReader(pcap_file) as packets:
            chunk_size = 10000
            flows = {}
            while True:
                chunk = packets.read_all(count=chunk_size)
                if not chunk:
                    break
                flow_stats = process_pcap_chunk(chunk)
                for key, flow in flow_stats.items():
                    if key not in flows:
                        flows[key] = flow
                    else:
                        flows[key] = merge_flows(flows[key], flow)
            return flows
    except Exception as e:
        print(f"An error occurred while processing {pcap_file}: {str(e)}")
        return {}

def merge_flows(flow1, flow2):
    for key in flow1:
        if key in ['start_time', 'last_time']:
            flow1[key] = min(flow1[key], flow2[key]) if key == 'start_time' else max(flow1[key], flow2[key])
        elif key in ['fwd_iat', 'bwd_iat', 'fwd_pkts_payload', 'bwd_pkts_payload', 'active_times', 'idle_times']:
            flow1[key] += flow2[key]
        elif key in ['fwd_window_sizes', 'bwd_window_sizes']:
            flow1[key] = flow1[key] + flow2[key]
        else:
            flow1[key] += flow2[key]
    return flow1

def filter_flow_attributes(flow, attributes):
    return {key: value for key, value in flow.items() if key in attributes}

def save_flows_to_csv(flows, output_file, attributes):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=attributes)
        writer.writeheader()
        for flow in flows.values():
            flow = calculate_flow_statistics(flow)
            filtered_flow = filter_flow_attributes(flow, attributes)
            writer.writerow(filtered_flow)

def process_pcap_file(pcap_file, output_dir, attributes):
    try:
        packets = rdpcap(pcap_file)
        flow_stats = process_pcap_chunk(packets)

        for flow in flow_stats.values():
            calculate_flow_statistics(flow)

        output_file = os.path.join(output_dir, os.path.basename(pcap_file) + '.csv')
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, all_fieldnames=attributes)
            writer.writeheader()
            for flow in flow_stats.values():
                writer.writerow({k: flow.get(k, '') for k in attributes})

        print(f"Processed {pcap_file} and saved results to {output_file}")
    except Exception as e:
        print(f"An error occurred while processing {pcap_file}: {str(e)}")


def extract_and_process_tar(tar_file, output_dir, attributes):
    try:
        with tarfile.open(tar_file, 'r:*') as tar:
            temp_dir = os.path.join(output_dir, 'temp_extracted')
            os.makedirs(temp_dir, exist_ok=True)
            tar.extractall(path=temp_dir)
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.pcap'):
                        pcap_file = os.path.join(root, file)
                        process_pcap_file(pcap_file, output_dir, attributes)
            
            # Clean up temporary directory
            for root, dirs, files in os.walk(temp_dir, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(temp_dir)
    except Exception as e:
        print(f"An error occurred while processing {tar_file}: {str(e)}")

def cpu_usage_check():
    return psutil.cpu_percent() < 70

if __name__ == "__main__":
    args = parser.parse_args()
    input_path = args.input
    output_dir = args.output

    # Parse the parameters input
    try:
        if args.parameters.startswith('[') and args.parameters.endswith(']'):
            attributes = ast.literal_eval(args.parameters)
            if not isinstance(attributes, list):
                raise ValueError("Invalid format for multiple parameters")
        else:
            attributes = [args.parameters.strip('"')]
    except:
        print("Error parsing parameters. Please use the format: \"param1\" or [\"param1\", \"param2\", ...]")
        sys.exit(1)

    # Validate the provided parameters
    invalid_params = set(attributes) - set(all_fieldnames)
    if invalid_params:
        print(f"Invalid parameters provided: {', '.join(invalid_params)}")
        print(f"Valid parameters are: {', '.join(all_fieldnames)}")
        sys.exit(1)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    def process_file(file_path):
        while not cpu_usage_check():
            time.sleep(1)  # Wait for 1 second before checking again
        
        if file_path.endswith(('.tar', '.tar.gz')) and args.tar:
            extract_and_process_tar(file_path, output_dir, attributes)
        elif file_path.endswith('.pcap'):
            process_pcap_file(file_path, output_dir, attributes)

    if os.path.isfile(input_path):
        process_file(input_path)
    elif os.path.isdir(input_path):
        for file in os.listdir(input_path):
            file_path = os.path.join(input_path, file)
            process_file(file_path)
    else:
        print(f"Invalid input path: {input_path}")

    print("Processing complete.")