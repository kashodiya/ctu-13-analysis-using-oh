#!/usr/bin/env python3
"""
Create sample CTU-13 dataset for demonstration purposes
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
from pathlib import Path

def create_sample_netflow_data(n_flows=1000):
    """Create sample NetFlow data that mimics CTU-13 format"""
    
    # Set random seed for reproducibility
    np.random.seed(42)
    random.seed(42)
    
    # Sample IP addresses
    normal_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30', '10.0.0.5', '10.0.0.15']
    botnet_ips = ['192.168.1.100', '192.168.1.101']  # Infected machines
    external_ips = ['8.8.8.8', '1.1.1.1', '74.125.224.72', '157.240.12.35', '185.199.108.153']
    c2_servers = ['203.0.113.10', '198.51.100.20']  # C&C servers
    
    # Common ports
    normal_ports = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995]
    malicious_ports = [1337, 4444, 6667, 8080, 9999]
    
    flows = []
    start_time = datetime.now() - timedelta(hours=2)
    
    for i in range(n_flows):
        # Determine flow type
        flow_type = np.random.choice(['normal', 'botnet', 'c2', 'background'], 
                                   p=[0.6, 0.2, 0.1, 0.1])
        
        # Generate timestamp
        timestamp = start_time + timedelta(seconds=random.randint(0, 7200))
        
        if flow_type == 'normal':
            src_addr = random.choice(normal_ips)
            dst_addr = random.choice(external_ips + normal_ips)
            dst_port = random.choice(normal_ports)
            src_port = random.randint(1024, 65535)
            proto = random.choice(['tcp', 'udp'])
            duration = np.random.exponential(5.0)
            tot_pkts = random.randint(1, 100)
            tot_bytes = random.randint(64, 10000)
            label = 'Normal'
            
        elif flow_type == 'botnet':
            src_addr = random.choice(botnet_ips)
            dst_addr = random.choice(external_ips)
            dst_port = random.choice(normal_ports + malicious_ports)
            src_port = random.randint(1024, 65535)
            proto = 'tcp'
            duration = np.random.exponential(10.0)
            tot_pkts = random.randint(5, 200)
            tot_bytes = random.randint(100, 50000)
            label = 'Botnet'
            
        elif flow_type == 'c2':
            src_addr = random.choice(botnet_ips)
            dst_addr = random.choice(c2_servers)
            dst_port = random.choice(malicious_ports)
            src_port = random.randint(1024, 65535)
            proto = 'tcp'
            duration = np.random.exponential(2.0)  # Short, regular communications
            tot_pkts = random.randint(1, 20)
            tot_bytes = random.randint(64, 1000)  # Small payloads
            label = 'C&C'
            
        else:  # background
            src_addr = random.choice(normal_ips + external_ips)
            dst_addr = random.choice(normal_ips + external_ips)
            dst_port = random.choice(normal_ports)
            src_port = random.randint(1024, 65535)
            proto = random.choice(['tcp', 'udp', 'icmp'])
            duration = np.random.exponential(1.0)
            tot_pkts = random.randint(1, 50)
            tot_bytes = random.randint(64, 5000)
            label = 'Background'
        
        src_bytes = random.randint(int(tot_bytes * 0.3), int(tot_bytes * 0.8))
        
        flow = {
            'StartTime': timestamp.strftime('%Y/%m/%d %H:%M:%S.%f'),
            'Dur': round(duration, 6),
            'Proto': proto,
            'SrcAddr': src_addr,
            'Sport': src_port,
            'Dir': '->',
            'DstAddr': dst_addr,
            'Dport': dst_port,
            'State': 'CON' if proto == 'tcp' else 'INT',
            'sTos': 0,
            'dTos': 0,
            'TotPkts': tot_pkts,
            'TotBytes': tot_bytes,
            'SrcBytes': src_bytes,
            'Label': label
        }
        
        flows.append(flow)
    
    return flows

def save_sample_binetflow(flows, filename):
    """Save flows in binetflow format"""
    with open(filename, 'w') as f:
        # Write header (simplified)
        f.write("# Sample CTU-13 NetFlow data for demonstration\n")
        f.write("# StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n")
        
        for flow in flows:
            line = f"{flow['StartTime']},{flow['Dur']},{flow['Proto']},{flow['SrcAddr']},{flow['Sport']},{flow['Dir']},{flow['DstAddr']},{flow['Dport']},{flow['State']},{flow['sTos']},{flow['dTos']},{flow['TotPkts']},{flow['TotBytes']},{flow['SrcBytes']},{flow['Label']}\n"
            f.write(line)

def main():
    """Create sample data files"""
    print("Creating sample CTU-13 dataset...")
    
    # Create data directory
    data_dir = Path('data/raw')
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Create sample scenarios
    scenarios = [1, 2]  # Create 2 sample scenarios
    
    for scenario_num in scenarios:
        print(f"Creating scenario {scenario_num}...")
        
        # Generate flows (more for scenario 1, less for scenario 2)
        n_flows = 2000 if scenario_num == 1 else 1000
        flows = create_sample_netflow_data(n_flows)
        
        # Save as binetflow file
        filename = data_dir / f"scenario_{scenario_num:02d}_capture.binetflow"
        save_sample_binetflow(flows, filename)
        
        print(f"Created {filename} with {len(flows)} flows")
    
    print("Sample dataset creation completed!")
    print("\nYou can now run:")
    print("  python main.py parse")
    print("  python main.py analyze --all")
    print("  python main.py visualize")

if __name__ == '__main__':
    main()