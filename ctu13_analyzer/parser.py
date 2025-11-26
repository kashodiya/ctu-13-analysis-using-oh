"""
CTU-13 Dataset Parser

This module handles parsing the .biargus NetFlow files and converting them to pandas DataFrames.
"""

import pandas as pd
import numpy as np
import logging
from pathlib import Path
import re
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CTU13Parser:
    """Parses CTU-13 NetFlow data files"""
    
    def __init__(self, data_dir="data/raw"):
        self.data_dir = Path(data_dir)
        
        # Standard NetFlow columns based on Argus format
        self.netflow_columns = [
            'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir', 'DstAddr', 'Dport',
            'State', 'sTos', 'dTos', 'TotPkts', 'TotBytes', 'SrcBytes', 'Label'
        ]
    
    def parse_biargus_file(self, filepath):
        """Parse a .biargus NetFlow file"""
        try:
            filepath = Path(filepath)
            logger.info(f"Parsing NetFlow file: {filepath.name}")
            
            # Read the file line by line and parse
            flows = []
            with open(filepath, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        flow_data = self._parse_netflow_line(line)
                        if flow_data:
                            flows.append(flow_data)
                    except Exception as e:
                        logger.warning(f"Error parsing line {line_num}: {e}")
                        continue
            
            if not flows:
                logger.error("No valid flows found in file")
                return None
            
            df = pd.DataFrame(flows)
            logger.info(f"Parsed {len(df)} NetFlow records")
            
            # Clean and process the data
            df = self._clean_dataframe(df)
            
            return df
            
        except Exception as e:
            logger.error(f"Failed to parse file {filepath}: {e}")
            return None
    
    def _parse_netflow_line(self, line):
        """Parse a single NetFlow line"""
        # Handle both comma-separated and space-separated formats
        if ',' in line:
            fields = [field.strip() for field in line.split(',')]
        else:
            # Split by whitespace, handling multiple spaces
            fields = re.split(r'\s+', line.strip())
        
        if len(fields) < 14:
            return None
        
        try:
            flow_data = {
                'StartTime': fields[0],
                'Dur': float(fields[1]) if fields[1] != '*' else 0.0,
                'Proto': fields[2],
                'SrcAddr': fields[3],
                'Sport': fields[4],
                'Dir': fields[5],
                'DstAddr': fields[6],
                'Dport': fields[7],
                'State': fields[8],
                'sTos': fields[9],
                'dTos': fields[10],
                'TotPkts': int(fields[11]) if fields[11] != '*' else 0,
                'TotBytes': int(fields[12]) if fields[12] != '*' else 0,
                'SrcBytes': int(fields[13]) if fields[13] != '*' else 0,
                'Label': fields[14] if len(fields) > 14 else 'Unknown'
            }
            return flow_data
            
        except (ValueError, IndexError) as e:
            logger.debug(f"Error parsing flow data: {e}")
            return None
    
    def _clean_dataframe(self, df):
        """Clean and process the NetFlow DataFrame"""
        # Convert timestamp
        df['StartTime'] = pd.to_datetime(df['StartTime'], errors='coerce')
        
        # Extract port numbers (remove service names if present)
        df['SrcPort'] = df['Sport'].apply(self._extract_port)
        df['DstPort'] = df['Dport'].apply(self._extract_port)
        
        # Calculate derived features
        df['DstBytes'] = df['TotBytes'] - df['SrcBytes']
        df['PktSize'] = df['TotBytes'] / df['TotPkts'].replace(0, 1)
        
        # Categorize labels
        df['LabelCategory'] = df['Label'].apply(self._categorize_label)
        
        # Add IP address features
        df['SrcIP_Private'] = df['SrcAddr'].apply(self._is_private_ip)
        df['DstIP_Private'] = df['DstAddr'].apply(self._is_private_ip)
        
        # Protocol categorization
        df['ProtoCategory'] = df['Proto'].apply(self._categorize_protocol)
        
        return df
    
    def _extract_port(self, port_str):
        """Extract numeric port from port string"""
        try:
            # Handle cases like "http" -> 80, "https" -> 443, etc.
            port_map = {
                'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 'telnet': 23,
                'smtp': 25, 'dns': 53, 'pop3': 110, 'imap': 143, 'snmp': 161
            }
            
            if port_str.isdigit():
                return int(port_str)
            elif port_str.lower() in port_map:
                return port_map[port_str.lower()]
            else:
                return 0
        except:
            return 0
    
    def _categorize_label(self, label):
        """Categorize the flow label"""
        if pd.isna(label) or label == 'Unknown':
            return 'Unknown'
        
        label_lower = str(label).lower()
        
        if 'botnet' in label_lower:
            return 'Botnet'
        elif 'c&c' in label_lower or 'cc' in label_lower:
            return 'C&C'
        elif 'normal' in label_lower:
            return 'Normal'
        elif 'background' in label_lower:
            return 'Background'
        else:
            return 'Other'
    
    def _is_private_ip(self, ip_str):
        """Check if IP address is private"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False
    
    def _categorize_protocol(self, proto):
        """Categorize protocol types"""
        proto_lower = str(proto).lower()
        
        if proto_lower in ['tcp']:
            return 'TCP'
        elif proto_lower in ['udp']:
            return 'UDP'
        elif proto_lower in ['icmp']:
            return 'ICMP'
        else:
            return 'Other'
    
    def parse_all_scenarios(self):
        """Parse all available .binetflow files"""
        binetflow_files = list(self.data_dir.glob("*.binetflow"))
        
        if not binetflow_files:
            logger.warning("No .binetflow files found in data directory")
            return {}
        
        parsed_data = {}
        for file_path in binetflow_files:
            scenario_name = file_path.stem
            df = self.parse_biargus_file(file_path)
            if df is not None:
                parsed_data[scenario_name] = df
        
        logger.info(f"Successfully parsed {len(parsed_data)} scenario files")
        return parsed_data
    
    def get_dataset_summary(self, df):
        """Generate summary statistics for a dataset"""
        summary = {
            'total_flows': len(df),
            'time_range': {
                'start': str(df['StartTime'].min()),
                'end': str(df['StartTime'].max()),
                'duration_hours': (df['StartTime'].max() - df['StartTime'].min()).total_seconds() / 3600
            },
            'label_distribution': df['LabelCategory'].value_counts().to_dict(),
            'protocol_distribution': df['ProtoCategory'].value_counts().to_dict(),
            'unique_src_ips': df['SrcAddr'].nunique(),
            'unique_dst_ips': df['DstAddr'].nunique(),
            'total_bytes': int(df['TotBytes'].sum()),
            'total_packets': int(df['TotPkts'].sum()),
            'avg_flow_duration': float(df['Dur'].mean()),
            'avg_packet_size': float(df['PktSize'].mean())
        }
        
        return summary
    
    def save_processed_data(self, data_dict, output_dir="data/processed"):
        """Save processed DataFrames to CSV files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for scenario_name, df in data_dict.items():
            csv_path = output_path / f"{scenario_name}_processed.csv"
            df.to_csv(csv_path, index=False)
            logger.info(f"Saved processed data to {csv_path}")
        
        # Save combined summary
        summary_data = []
        for scenario_name, df in data_dict.items():
            summary = self.get_dataset_summary(df)
            summary['scenario'] = scenario_name
            summary_data.append(summary)
        
        summary_df = pd.DataFrame(summary_data)
        summary_path = output_path / "dataset_summary.csv"
        summary_df.to_csv(summary_path, index=False)
        logger.info(f"Saved dataset summary to {summary_path}")
        
        return True