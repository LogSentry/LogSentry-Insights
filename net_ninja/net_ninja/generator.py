import pandas as pd
import numpy as np
from collections import Counter
import requests
import re
from scipy.stats import entropy
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

def process_network_csv(csv_path, output_path=None):
    """
    Process a network traffic CSV file to generate enhanced features for attack detection.
    
    :param csv_path: str, path to the input CSV file
    :param output_path: str, optional path to save the output CSV file
    :return: pandas DataFrame with enhanced features
    """
    def get_country(ip):
        try:
            response = requests.get(f"https://ipapi.co/{ip}/country/", timeout=5)
            return response.text.strip()
        except:
            return "Unknown"

    def calculate_entropy(payload):
        return entropy(pd.Series(list(str(payload))).value_counts())

    # Read the CSV file
    df = pd.read_csv(csv_path)
    
    # 1. Traffic Volume Metrics
    df['Requests_per_Second'] = df['Flow Pkts/s']
    df['Total_Bandwidth_Consumption'] = df['TotLen Fwd Pkts'] + df['TotLen Bwd Pkts']
    df['Packet_Rate'] = df['Flow Pkts/s']

    # 2. Protocol-Specific Features
    df['TCP_SYN_Packet_Count'] = df['SYN Flag Cnt']
    df['UDP_Packet_Count'] = df[df['Protocol'] == 17]['Tot Fwd Pkts'] + df[df['Protocol'] == 17]['Tot Bwd Pkts']
    df['ICMP_Packet_Count'] = df[df['Protocol'] == 1]['Tot Fwd Pkts'] + df[df['Protocol'] == 1]['Tot Bwd Pkts']

    # 3. IP Address Diversity
    df['Unique_Source_IPs'] = df.groupby('Flow ID')['Src IP'].transform('nunique')

    # 4. Time-Based Features
    df['Connection_Duration'] = df['Flow Duration']
    df['Inter_Arrival_Time'] = df['Flow IAT Mean']
    df['Time_Pattern'] = pd.to_datetime(df['Timestamp']).dt.hour

    # 5. Payload Analysis
    df['Payload_Size'] = df['TotLen Fwd Pkts'] + df['TotLen Bwd Pkts']
    df['Payload_Entropy'] = (df['TotLen Fwd Pkts'] + df['TotLen Bwd Pkts']).apply(calculate_entropy)

    # 6. Flag Analysis
    flag_columns = ['FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt']
    df['Total_Flags'] = df[flag_columns].sum(axis=1)
    df['Flag_Distribution'] = df[flag_columns].apply(lambda row: ','.join(f"{col.split()[0]}:{val}" for col, val in row.items()), axis=1)

    # 7. Packet Length Statistics
    df['Fwd_Packet_Length_Std'] = df['Fwd Pkt Len Std']
    df['Bwd_Packet_Length_Std'] = df['Bwd Pkt Len Std']
    df['Packet_Length_Variance'] = df['Pkt Len Var']

    # 8. Flow Inter-arrival Time Statistics
    df['Fwd_IAT_Std'] = df['Fwd IAT Std']
    df['Bwd_IAT_Std'] = df['Bwd IAT Std']
    df['Flow_IAT_Std'] = df['Flow IAT Std']

    # 9. Active and Idle Time
    df['Active_Time_Mean'] = df['Active Mean']
    df['Active_Time_Std'] = df['Active Std']
    df['Idle_Time_Mean'] = df['Idle Mean']
    df['Idle_Time_Std'] = df['Idle Std']

    # 10. Subflow Statistics
    df['Subflow_Fwd_Packets'] = df['Subflow Fwd Pkts']
    df['Subflow_Bwd_Packets'] = df['Subflow Bwd Pkts']
    df['Subflow_Fwd_Bytes'] = df['Subflow Fwd Byts']
    df['Subflow_Bwd_Bytes'] = df['Subflow Bwd Byts']

    # 11. Window Size Statistics
    df['Init_Win_Bytes_Forward'] = df['Init Fwd Win Byts']
    df['Init_Win_Bytes_Backward'] = df['Init Bwd Win Byts']

    # 12. Packet Count Ratio
    df['Packet_Count_Ratio'] = df['Tot Fwd Pkts'] / (df['Tot Bwd Pkts'] + 1)  # Adding 1 to avoid division by zero

    # 13. Byte Count Ratio
    df['Byte_Count_Ratio'] = df['TotLen Fwd Pkts'] / (df['TotLen Bwd Pkts'] + 1)  # Adding 1 to avoid division by zero

    # 14. PSH and URG Flag Ratios
    total_packets = df['Tot Fwd Pkts'] + df['Tot Bwd Pkts']
    df['PSH_Flag_Ratio'] = (df['Fwd PSH Flags'] + df['Bwd PSH Flags']) / total_packets
    df['URG_Flag_Ratio'] = (df['Fwd URG Flags'] + df['Bwd URG Flags']) / total_packets

    # 15. Average Packet Size
    df['Avg_Packet_Size'] = (df['TotLen Fwd Pkts'] + df['TotLen Bwd Pkts']) / total_packets

    # Multithreading for geolocation API calls
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(get_country, ip): ip for ip in df['Src IP'].unique()}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                country = future.result()
                df.loc[df['Src IP'] == ip, 'Source_IP_Country'] = country
            except Exception as exc:
                print(f"{ip} generated an exception: {exc}")

    if output_path:
        df.to_csv(output_path, index=False)
        print(f"Enhanced network features have been generated and saved to '{output_path}'")
    
    return df

# Usage example:
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python generator.py <path_to_csv_file>")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    process_network_csv(csv_path)
