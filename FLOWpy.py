import argparse
import csv
import os
import numpy as np
import tarfile
from scapy.all import rdpcap, IP, TCP, UDP
from scapy.all import PcapReader
import concurrent.futures
import psutil
import math
from decimal import Decimal
import logging
import multiprocessing as mp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Define the fieldnames for the CSV file... the amout of thimes this shit annyed me is F**king crazyyyyyyyyyy
fieldnames = [
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


def process_pcap_chunk(packets):
    flow_stats = {}
    for packet in packets:
        if IP in packet and (TCP in packet or UDP in packet):
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
    flow['flow_pkts_per_sec'] = safe_division(flow['fwd_pkts_tot'] + flow['bwd_pkts_tot'], flow['flow_duration'])
    
    # Calculate payload statistics
    fwd_payload = np.array([to_float(x) for x in flow['fwd_pkts_payload']])
    bwd_payload = np.array([to_float(x) for x in flow['bwd_pkts_payload']])
    flow_payload = np.concatenate([fwd_payload, bwd_payload])
    
    for direction, payload in [('fwd', fwd_payload), ('bwd', bwd_payload), ('flow', flow_payload)]:
        if len(payload) > 0:
            flow[f'{direction}_pkts_payload_max'] = float(np.max(payload))
            flow[f'{direction}_pkts_payload_min'] = float(np.min(payload))
            flow[f'{direction}_pkts_payload_tot'] = float(np.sum(payload))
            flow[f'{direction}_pkts_payload_avg'] = float(np.mean(payload))
            flow[f'{direction}_pkts_payload_std'] = float(np.std(payload))
        else:
            flow[f'{direction}_pkts_payload_max'] = flow[f'{direction}_pkts_payload_min'] = flow[f'{direction}_pkts_payload_tot'] = flow[f'{direction}_pkts_payload_avg'] = flow[f'{direction}_pkts_payload_std'] = 0.0
    
    flow['payload_bytes_per_second'] = safe_division(flow['flow_pkts_payload_tot'], flow['flow_duration'])
    
    # Calculate IAT statistics
    fwd_iat = np.array([to_float(x) for x in flow['fwd_iat']])
    bwd_iat = np.array([to_float(x) for x in flow['bwd_iat']])
    flow_iat = np.concatenate([fwd_iat, bwd_iat])
    
    for direction, iat in [('fwd', fwd_iat), ('bwd', bwd_iat), ('flow', flow_iat)]:
        if len(iat) > 0:
            flow[f'{direction}_iat_max'] = float(np.max(iat))
            flow[f'{direction}_iat_min'] = float(np.min(iat))
            flow[f'{direction}_iat_tot'] = float(np.sum(iat))
            flow[f'{direction}_iat_avg'] = float(np.mean(iat))
            flow[f'{direction}_iat_std'] = float(np.std(iat))
        else:
            flow[f'{direction}_iat_max'] = flow[f'{direction}_iat_min'] = flow[f'{direction}_iat_tot'] = flow[f'{direction}_iat_avg'] = flow[f'{direction}_iat_std'] = 0.0
    
    # Calculate active and idle times
    active_times = np.array([to_float(t) for t in flow['active_times'] if t > 0])
    idle_times = np.array([to_float(t) for t in flow['idle_times']])
    
    for time_type, times in [('active', active_times), ('idle', idle_times)]:
        if len(times) > 0:
            flow[f'{time_type}_max'] = float(np.max(times))
            flow[f'{time_type}_min'] = float(np.min(times))
            flow[f'{time_type}_tot'] = float(np.sum(times))
            flow[f'{time_type}_avg'] = float(np.mean(times))
            flow[f'{time_type}_std'] = float(np.std(times))
        else:
            flow[f'{time_type}_max'] = flow[f'{time_type}_min'] = flow[f'{time_type}_tot'] = flow[f'{time_type}_avg'] = flow[f'{time_type}_std'] = 0.0
    
    # Calculate other statistics
    flow['down_up_ratio'] = safe_division(flow['bwd_pkts_tot'], flow['fwd_pkts_tot'])
    flow['average_packet_size'] = safe_division(flow['flow_pkts_payload_tot'], flow['fwd_pkts_tot'] + flow['bwd_pkts_tot'])
    flow['fwd_header_size_min'] = min(to_float(flow['fwd_header_size_tot']), to_float(flow['fwd_pkts_tot']))
    flow['fwd_header_size_max'] = max(to_float(flow['fwd_header_size_tot']), to_float(flow['fwd_pkts_tot']))
    flow['bwd_header_size_min'] = min(to_float(flow['bwd_header_size_tot']), to_float(flow['bwd_pkts_tot']))
    flow['bwd_header_size_max'] = max(to_float(flow['bwd_header_size_tot']), to_float(flow['bwd_pkts_tot']))
    
    # Calculate subflow statistics
    flow['fwd_subflow_pkts'] = flow['fwd_pkts_tot']
    flow['bwd_subflow_pkts'] = flow['bwd_pkts_tot']
    flow['fwd_subflow_bytes'] = flow['fwd_pkts_payload_tot']
    flow['bwd_subflow_bytes'] = flow['bwd_pkts_payload_tot']
    
    # Calculate bulk statistics (simplified version)
    flow['fwd_bulk_bytes'] = flow['fwd_pkts_payload_tot']
    flow['bwd_bulk_bytes'] = flow['bwd_pkts_payload_tot']
    flow['fwd_bulk_packets'] = flow['fwd_pkts_tot']
    flow['bwd_bulk_packets'] = flow['bwd_pkts_tot']
    flow['fwd_bulk_rate'] = safe_division(flow['fwd_bulk_bytes'], flow['flow_duration'])
    flow['bwd_bulk_rate'] = safe_division(flow['bwd_bulk_bytes'], flow['flow_duration'])

    # Window sizes
    flow['fwd_init_window_size'] = flow['fwd_window_sizes'][0] if flow['fwd_window_sizes'] else 0
    flow['bwd_init_window_size'] = flow['bwd_window_sizes'][0] if flow['bwd_window_sizes'] else 0
    flow['fwd_last_window_size'] = flow['fwd_window_sizes'][-1] if flow['fwd_window_sizes'] else 0
    flow['bwd_last_window_size'] = flow['bwd_window_sizes'][-1] if flow['bwd_window_sizes'] else 0

    # Clean up temporary data
    del flow['fwd_pkts_payload']
    del flow['bwd_pkts_payload']
    del flow['fwd_iat']
    del flow['bwd_iat']
    del flow['active_times']
    del flow['idle_times']
    del flow['fwd_window_sizes']
    del flow['bwd_window_sizes']

    return flow

def process_pcap(pcap_file, output_csv, chunk_size=5*1024*1024*1024):
    flow_stats = {}
    
    with PcapReader(pcap_file) as pcap_reader:
        chunk = []
        for packet in pcap_reader:
            chunk.append(packet)
            if len(chunk) * packet.wirelen > chunk_size:
                chunk_stats = process_pcap_chunk(chunk)
                for key, value in chunk_stats.items():
                    if key in flow_stats:
                        flow_stats[key] = {**flow_stats[key], **value}
                    else:
                        flow_stats[key] = value
                chunk = []
    
    if chunk:
        chunk_stats = process_pcap_chunk(chunk)
        for key, value in chunk_stats.items():
            if key in flow_stats:
                flow_stats[key] = {**flow_stats[key], **value}
            else:
                flow_stats[key] = value

    # Calculate final statistics for each flow
    for key in flow_stats:
        flow_stats[key] = calculate_flow_statistics(flow_stats[key])

    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for flow in flow_stats.values():
            writer.writerow(flow)

def process_file(args):
    file_path, output_dir, chunk_size = args
    if file_path.endswith('.pcap'):
        output_csv = os.path.join(output_dir, os.path.basename(file_path).replace('.pcap', '.csv'))
        process_pcap(file_path, output_csv, chunk_size)
    elif file_path.endswith('.tar.gz'):
        with tarfile.open(file_path, 'r:gz') as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith('.pcap'):
                    member_file = tar.extractfile(member)
                    pcap_file = os.path.join(output_dir, os.path.basename(member.name))
                    with open(pcap_file, 'wb') as f:
                        f.write(member_file.read())
                    output_csv = pcap_file.replace('.pcap', '.csv')
                    process_pcap(pcap_file, output_csv, chunk_size)

def get_optimal_workers():
    physical_cores = psutil.cpu_count(logical=False)
    available_memory = psutil.virtual_memory().available / (1024 * 1024 * 1024)
    
    workers_by_cores = max(1, physical_cores - 1)
    workers_by_memory = max(1, int(available_memory / 2))
    
    return min(workers_by_cores, workers_by_memory)

def process_files(input_dir, output_dir, recursive=False, chunk_size=5*1024*1024*1024):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    file_list = []
    if recursive:
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.endswith(('.pcap', '.tar.gz')):
                    file_list.append((os.path.join(root, file), output_dir, chunk_size))
    else:
        for file in os.listdir(input_dir):
            if file.endswith(('.pcap', '.tar.gz')):
                file_list.append((os.path.join(input_dir, file), output_dir, chunk_size))

    optimal_workers = get_optimal_workers()
    
    with concurrent.futures.ProcessPoolExecutor(max_workers=optimal_workers) as executor:
        futures = [executor.submit(process_file, args) for args in file_list]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                print(f'An exception occurred: {exc}')

def main():
    parser = argparse.ArgumentParser(description='Process PCAP files and extract network traffic features.')
    parser.add_argument('-i', '--input', required=True, help='Input directory containing PCAP files or TAR.GZ files')
    parser.add_argument('-o', '--output', required=True, help='Output directory for CSV files')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively process files in subdirectories')
    parser.add_argument('-d', '--directory', action='store_true', help='Process directory of .pcap files')
    parser.add_argument('-t', '--tar', action='store_true', help='Process .tar.gz files')
    parser.add_argument('--chunk-size', type=int, default=5*1024*1024*1024, help='Chunk size for processing large files (in bytes)')
    
    args = parser.parse_args()
    
    process_files(args.input, args.output, args.recursive or args.directory, args.chunk_size)

if __name__ == "__main__":
    main()