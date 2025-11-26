#!/usr/bin/env python3
"""
Create enhanced sample data for showcase visualizations
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
from pathlib import Path

def create_showcase_dataset():
    """Create a more comprehensive dataset for better visualizations"""
    
    # Set random seed for reproducibility
    np.random.seed(42)
    random.seed(42)
    
    # Create more diverse data
    n_flows = 2000  # Increased from 1000
    
    # Time range - 24 hours of data
    start_time = datetime(2023, 8, 10, 0, 0, 0)
    end_time = start_time + timedelta(hours=24)
    
    # Generate timestamps with realistic patterns (more activity during business hours)
    timestamps = []
    for i in range(n_flows):
        # Create realistic time distribution
        hour_weight = np.random.choice([0.3, 1.0, 0.5], p=[0.3, 0.4, 0.3])  # Night, day, evening
        random_time = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )
        timestamps.append(random_time)
    
    timestamps.sort()
    
    # More realistic IP addresses
    internal_ips = [
        '192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25',
        '192.168.1.30', '192.168.1.35', '192.168.1.40', '192.168.1.45',
        '10.0.0.5', '10.0.0.10', '10.0.0.15', '10.0.0.20',
        '172.16.1.10', '172.16.1.15', '172.16.1.20'
    ]
    
    external_ips = [
        '8.8.8.8', '1.1.1.1', '208.67.222.222',  # DNS servers
        '74.125.224.72', '142.250.191.14',       # Google
        '157.240.241.35', '31.13.64.35',         # Facebook
        '52.84.124.12', '54.230.87.15',          # AWS/CloudFront
        '185.199.108.153', '140.82.112.4',       # GitHub
        '23.56.78.90', '45.67.89.123',           # Suspicious IPs
        '198.51.100.42', '203.0.113.15'          # More external IPs
    ]
    
    # Botnet C&C servers
    cc_servers = ['23.56.78.90', '45.67.89.123', '198.51.100.42']
    
    flows = []
    
    for i, timestamp in enumerate(timestamps):
        # Determine flow type
        flow_type = np.random.choice(['normal', 'botnet', 'scanning', 'dns_tunnel'], 
                                   p=[0.7, 0.15, 0.1, 0.05])
        
        if flow_type == 'normal':
            src_addr = np.random.choice(internal_ips)
            dst_addr = np.random.choice(external_ips[:8])  # Normal external services
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.choice([80, 443, 53, 25, 110, 993, 995])
            protocol = 'tcp' if dst_port != 53 else np.random.choice(['tcp', 'udp'])
            tot_bytes = np.random.randint(100, 50000)
            src_bytes = int(tot_bytes * np.random.uniform(0.1, 0.9))
            duration = np.random.uniform(0.1, 300)
            label = 'BENIGN'
            
        elif flow_type == 'botnet':
            src_addr = np.random.choice(internal_ips[:5])  # Infected machines
            dst_addr = np.random.choice(cc_servers)
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.choice([8080, 443, 80, 9999, 1337])
            protocol = 'tcp'
            tot_bytes = np.random.randint(50, 5000)  # Smaller, regular communications
            src_bytes = int(tot_bytes * np.random.uniform(0.3, 0.7))
            duration = np.random.uniform(1, 60)
            label = 'Botnet'
            
        elif flow_type == 'scanning':
            src_addr = np.random.choice(external_ips[8:])  # Suspicious external IPs
            dst_addr = np.random.choice(internal_ips)
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.choice([22, 23, 80, 443, 21, 25, 53, 135, 139, 445])
            protocol = 'tcp'
            tot_bytes = np.random.randint(40, 200)  # Small probe packets
            src_bytes = int(tot_bytes * 0.5)
            duration = np.random.uniform(0.1, 5)
            label = 'PortScan'
            
        elif flow_type == 'dns_tunnel':
            src_addr = np.random.choice(internal_ips[:3])  # Few infected machines
            dst_addr = '8.8.8.8'  # DNS server
            src_port = np.random.randint(1024, 65535)
            dst_port = 53
            protocol = 'udp'
            tot_bytes = np.random.randint(200, 1500)  # Larger DNS queries
            src_bytes = int(tot_bytes * 0.6)
            duration = np.random.uniform(0.1, 2)
            label = 'DNSTunneling'
        
        # Create flow record
        flow = {
            'StartTime': timestamp.strftime('%Y/%m/%d %H:%M:%S.%f')[:-3],
            'Dur': f"{duration:.6f}",
            'Proto': protocol,
            'SrcAddr': src_addr,
            'Sport': src_port,
            'Dir': '->',
            'DstAddr': dst_addr,
            'Dport': dst_port,
            'State': 'CON' if protocol == 'tcp' else 'UNK',
            'sTos': 0,
            'dTos': 0,
            'TotPkts': max(2, int(tot_bytes / np.random.randint(64, 1500))),
            'TotBytes': tot_bytes,
            'SrcBytes': src_bytes,
            'Label': label
        }
        
        flows.append(flow)
    
    return flows

def save_showcase_data():
    """Save the showcase dataset"""
    flows = create_showcase_dataset()
    
    # Save as binetflow format
    output_dir = Path('data/raw')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / 'showcase_capture.binetflow'
    
    with open(output_file, 'w') as f:
        # Write header
        f.write("StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n")
        
        # Write flows
        for flow in flows:
            line = f"{flow['StartTime']},{flow['Dur']},{flow['Proto']},{flow['SrcAddr']}," \
                   f"{flow['Sport']},{flow['Dir']},{flow['DstAddr']},{flow['Dport']}," \
                   f"{flow['State']},{flow['sTos']},{flow['dTos']},{flow['TotPkts']}," \
                   f"{flow['TotBytes']},{flow['SrcBytes']},{flow['Label']}\n"
            f.write(line)
    
    print(f"Created showcase dataset with {len(flows)} flows")
    print(f"Saved to: {output_file}")
    
    # Print statistics
    df = pd.DataFrame(flows)
    print("\nDataset Statistics:")
    print(f"Total flows: {len(df)}")
    print(f"Label distribution:")
    print(df['Label'].value_counts())
    print(f"Protocol distribution:")
    print(df['Proto'].value_counts())
    print(f"Time range: {df['StartTime'].min()} to {df['StartTime'].max()}")

if __name__ == "__main__":
    save_showcase_data()