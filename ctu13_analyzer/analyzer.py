"""
CTU-13 Dataset Analyzer

This module provides comprehensive analysis capabilities for cybersecurity insights.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import logging
from collections import Counter
import ipaddress
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CTU13Analyzer:
    """Comprehensive analyzer for CTU-13 dataset"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        
    def analyze_traffic_patterns(self, df):
        """Analyze network traffic patterns"""
        logger.info("Analyzing traffic patterns...")
        
        analysis = {
            'temporal_patterns': self._analyze_temporal_patterns(df),
            'protocol_analysis': self._analyze_protocols(df),
            'port_analysis': self._analyze_ports(df),
            'ip_analysis': self._analyze_ip_addresses(df),
            'flow_characteristics': self._analyze_flow_characteristics(df)
        }
        
        return analysis
    
    def detect_anomalies(self, df, contamination=0.1):
        """Detect anomalous network flows using Isolation Forest"""
        logger.info("Detecting anomalies...")
        
        # Select numerical features for anomaly detection
        features = ['Dur', 'TotPkts', 'TotBytes', 'SrcBytes', 'DstBytes', 'PktSize', 'SrcPort', 'DstPort']
        
        # Prepare data
        X = df[features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        
        # Apply Isolation Forest
        iso_forest = IsolationForest(contamination=contamination, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X_scaled)
        
        # Add anomaly labels to dataframe
        df_with_anomalies = df.copy()
        df_with_anomalies['Anomaly'] = anomaly_labels
        df_with_anomalies['AnomalyScore'] = iso_forest.score_samples(X_scaled)
        
        # Analyze anomalies
        anomalies = df_with_anomalies[df_with_anomalies['Anomaly'] == -1]
        
        anomaly_analysis = {
            'total_anomalies': len(anomalies),
            'anomaly_percentage': len(anomalies) / len(df) * 100,
            'anomaly_by_label': anomalies['LabelCategory'].value_counts().to_dict(),
            'top_anomalous_ips': self._get_top_anomalous_ips(anomalies),
            'anomaly_protocols': anomalies['ProtoCategory'].value_counts().to_dict()
        }
        
        return df_with_anomalies, anomaly_analysis
    
    def detect_botnet_behavior(self, df):
        """Detect potential botnet behavior patterns"""
        logger.info("Analyzing botnet behavior patterns...")
        
        botnet_indicators = {
            'c2_communication': self._detect_c2_communication(df),
            'periodic_beaconing': self._detect_periodic_beaconing(df),
            'port_scanning': self._detect_port_scanning(df),
            'data_exfiltration': self._detect_data_exfiltration(df),
            'dns_tunneling': self._detect_dns_tunneling(df)
        }
        
        return botnet_indicators
    
    def cluster_network_behavior(self, df, n_clusters=5):
        """Cluster network flows by behavior patterns"""
        logger.info("Clustering network behavior...")
        
        # Select features for clustering
        features = ['Dur', 'TotPkts', 'TotBytes', 'SrcBytes', 'PktSize']
        X = df[features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        
        # Apply DBSCAN clustering
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        cluster_labels = dbscan.fit_predict(X_scaled)
        
        df_clustered = df.copy()
        df_clustered['Cluster'] = cluster_labels
        
        # Analyze clusters
        cluster_analysis = {}
        for cluster_id in np.unique(cluster_labels):
            if cluster_id == -1:  # Noise points
                continue
                
            cluster_data = df_clustered[df_clustered['Cluster'] == cluster_id]
            cluster_analysis[f'cluster_{cluster_id}'] = {
                'size': len(cluster_data),
                'avg_duration': cluster_data['Dur'].mean(),
                'avg_bytes': cluster_data['TotBytes'].mean(),
                'dominant_protocol': cluster_data['ProtoCategory'].mode().iloc[0] if not cluster_data['ProtoCategory'].mode().empty else 'Unknown',
                'label_distribution': cluster_data['LabelCategory'].value_counts().to_dict()
            }
        
        return df_clustered, cluster_analysis
    
    def generate_threat_intelligence(self, df):
        """Generate threat intelligence from the dataset"""
        logger.info("Generating threat intelligence...")
        
        threat_intel = {
            'malicious_ips': self._identify_malicious_ips(df),
            'suspicious_ports': self._identify_suspicious_ports(df),
            'attack_timeline': self._create_attack_timeline(df),
            'communication_patterns': self._analyze_communication_patterns(df),
            'payload_analysis': self._analyze_payload_characteristics(df)
        }
        
        return threat_intel
    
    def _analyze_temporal_patterns(self, df):
        """Analyze temporal patterns in network traffic"""
        df['Hour'] = df['StartTime'].dt.hour
        df['DayOfWeek'] = df['StartTime'].dt.dayofweek
        
        return {
            'hourly_distribution': df['Hour'].value_counts().sort_index().to_dict(),
            'daily_distribution': df['DayOfWeek'].value_counts().sort_index().to_dict(),
            'peak_hours': df.groupby('Hour')['TotBytes'].sum().nlargest(3).to_dict(),
            'traffic_by_label_hour': df.groupby(['Hour', 'LabelCategory']).size().unstack(fill_value=0).to_dict()
        }
    
    def _analyze_protocols(self, df):
        """Analyze protocol usage patterns"""
        return {
            'protocol_distribution': df['ProtoCategory'].value_counts().to_dict(),
            'bytes_by_protocol': df.groupby('ProtoCategory')['TotBytes'].sum().to_dict(),
            'malicious_protocols': df[df['LabelCategory'] == 'Botnet']['ProtoCategory'].value_counts().to_dict()
        }
    
    def _analyze_ports(self, df):
        """Analyze port usage patterns"""
        return {
            'top_src_ports': df['SrcPort'].value_counts().head(10).to_dict(),
            'top_dst_ports': df['DstPort'].value_counts().head(10).to_dict(),
            'malicious_dst_ports': df[df['LabelCategory'] == 'Botnet']['DstPort'].value_counts().head(10).to_dict(),
            'unusual_ports': self._find_unusual_ports(df)
        }
    
    def _analyze_ip_addresses(self, df):
        """Analyze IP address patterns"""
        return {
            'unique_src_ips': df['SrcAddr'].nunique(),
            'unique_dst_ips': df['DstAddr'].nunique(),
            'top_talkers': df.groupby('SrcAddr')['TotBytes'].sum().nlargest(10).to_dict(),
            'top_destinations': df.groupby('DstAddr')['TotBytes'].sum().nlargest(10).to_dict(),
            'private_vs_public': {
                'src_private': df['SrcIP_Private'].sum(),
                'dst_private': df['DstIP_Private'].sum()
            }
        }
    
    def _analyze_flow_characteristics(self, df):
        """Analyze flow characteristics"""
        return {
            'avg_flow_duration': df['Dur'].mean(),
            'avg_packet_size': df['PktSize'].mean(),
            'flow_size_distribution': df['TotBytes'].describe().to_dict(),
            'long_flows': len(df[df['Dur'] > df['Dur'].quantile(0.95)]),
            'large_flows': len(df[df['TotBytes'] > df['TotBytes'].quantile(0.95)])
        }
    
    def _detect_c2_communication(self, df):
        """Detect potential C&C communication patterns"""
        # Look for regular, small communications to external IPs
        external_comms = df[~df['DstIP_Private'] & (df['TotBytes'] < 1000)]
        
        c2_candidates = external_comms.groupby('DstAddr').agg({
            'StartTime': 'count',
            'TotBytes': 'mean',
            'Dur': 'mean'
        }).rename(columns={'StartTime': 'frequency'})
        
        # Filter for regular, small communications
        c2_suspects = c2_candidates[
            (c2_candidates['frequency'] > 10) & 
            (c2_candidates['TotBytes'] < 500)
        ]
        
        return {
            'potential_c2_servers': c2_suspects.to_dict('index'),
            'total_suspects': len(c2_suspects)
        }
    
    def _detect_periodic_beaconing(self, df):
        """Detect periodic beaconing behavior"""
        # Group by source-destination pairs
        comm_pairs = df.groupby(['SrcAddr', 'DstAddr'])['StartTime'].apply(list)
        
        beaconing_pairs = []
        for (src, dst), timestamps in comm_pairs.items():
            if len(timestamps) > 5:  # Need multiple communications
                timestamps.sort()
                intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                           for i in range(len(timestamps)-1)]
                
                # Check for regular intervals (low variance)
                if len(intervals) > 1:
                    interval_std = np.std(intervals)
                    interval_mean = np.mean(intervals)
                    
                    if interval_std < interval_mean * 0.3:  # Regular pattern
                        beaconing_pairs.append({
                            'src': src,
                            'dst': dst,
                            'avg_interval': interval_mean,
                            'communications': len(timestamps)
                        })
        
        return {
            'beaconing_pairs': beaconing_pairs,
            'total_beaconing': len(beaconing_pairs)
        }
    
    def _detect_port_scanning(self, df):
        """Detect port scanning activities"""
        # Look for sources connecting to many different ports on same destination
        port_scan_candidates = df.groupby(['SrcAddr', 'DstAddr']).agg({
            'DstPort': 'nunique',
            'StartTime': 'count'
        }).rename(columns={'StartTime': 'connections'})
        
        port_scans = port_scan_candidates[
            (port_scan_candidates['DstPort'] > 10) &
            (port_scan_candidates['connections'] > 20)
        ]
        
        # Convert tuple keys to strings for JSON serialization
        port_scan_dict = {}
        for (src, dst), data in port_scans.iterrows():
            port_scan_dict[f"{src}->{dst}"] = {
                'unique_ports': data['DstPort'],
                'total_connections': data['connections']
            }
        
        return {
            'port_scan_activities': port_scan_dict,
            'total_scanners': len(port_scans)
        }
    
    def _detect_data_exfiltration(self, df):
        """Detect potential data exfiltration"""
        # Look for large outbound transfers to external IPs
        outbound = df[~df['DstIP_Private']]
        large_transfers = outbound[outbound['SrcBytes'] > outbound['SrcBytes'].quantile(0.95)]
        
        exfil_candidates = large_transfers.groupby('SrcAddr').agg({
            'SrcBytes': 'sum',
            'DstAddr': 'nunique',
            'StartTime': 'count'
        }).rename(columns={'StartTime': 'sessions'})
        
        return {
            'potential_exfiltration': exfil_candidates.nlargest(10, 'SrcBytes').to_dict(),
            'total_large_transfers': len(large_transfers)
        }
    
    def _detect_dns_tunneling(self, df):
        """Detect potential DNS tunneling"""
        dns_traffic = df[df['DstPort'] == 53]
        
        if len(dns_traffic) == 0:
            return {'dns_tunneling_detected': False}
        
        # Look for unusual DNS patterns
        dns_analysis = dns_traffic.groupby('SrcAddr').agg({
            'TotBytes': ['sum', 'mean'],
            'StartTime': 'count'
        })
        
        dns_analysis.columns = ['total_bytes', 'avg_bytes', 'query_count']
        
        # Suspicious: high volume DNS queries
        suspicious_dns = dns_analysis[
            (dns_analysis['avg_bytes'] > 100) |  # Large DNS responses
            (dns_analysis['query_count'] > 1000)  # Too many queries
        ]
        
        return {
            'suspicious_dns_clients': suspicious_dns.to_dict(),
            'total_suspicious': len(suspicious_dns)
        }
    
    def _get_top_anomalous_ips(self, anomalies_df):
        """Get top anomalous IP addresses"""
        src_anomalies = anomalies_df['SrcAddr'].value_counts().head(10)
        dst_anomalies = anomalies_df['DstAddr'].value_counts().head(10)
        
        return {
            'top_anomalous_sources': src_anomalies.to_dict(),
            'top_anomalous_destinations': dst_anomalies.to_dict()
        }
    
    def _find_unusual_ports(self, df):
        """Find unusual port usage"""
        # Common ports
        common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
        
        unusual_dst_ports = df[~df['DstPort'].isin(common_ports)]['DstPort'].value_counts().head(10)
        
        return unusual_dst_ports.to_dict()
    
    def _identify_malicious_ips(self, df):
        """Identify malicious IP addresses"""
        malicious_flows = df[df['LabelCategory'].isin(['Botnet', 'C&C'])]
        
        malicious_src = malicious_flows['SrcAddr'].value_counts().head(20)
        malicious_dst = malicious_flows['DstAddr'].value_counts().head(20)
        
        return {
            'malicious_sources': malicious_src.to_dict(),
            'malicious_destinations': malicious_dst.to_dict()
        }
    
    def _identify_suspicious_ports(self, df):
        """Identify suspicious ports"""
        malicious_flows = df[df['LabelCategory'].isin(['Botnet', 'C&C'])]
        
        return {
            'malicious_dst_ports': malicious_flows['DstPort'].value_counts().head(20).to_dict(),
            'malicious_src_ports': malicious_flows['SrcPort'].value_counts().head(20).to_dict()
        }
    
    def _create_attack_timeline(self, df):
        """Create timeline of attack activities"""
        malicious_flows = df[df['LabelCategory'].isin(['Botnet', 'C&C'])]
        
        if len(malicious_flows) == 0:
            return {'no_attacks_detected': True}
        
        timeline = malicious_flows.groupby(malicious_flows['StartTime'].dt.floor('h')).agg({
            'LabelCategory': 'count',
            'TotBytes': 'sum',
            'SrcAddr': 'nunique'
        }).rename(columns={
            'LabelCategory': 'attack_count',
            'TotBytes': 'attack_bytes',
            'SrcAddr': 'unique_attackers'
        })
        
        # Convert timestamp index to string to avoid JSON serialization issues
        timeline_dict = {}
        for timestamp, row in timeline.iterrows():
            timeline_dict[str(timestamp)] = {
                'attack_count': int(row['attack_count']),
                'attack_bytes': int(row['attack_bytes']),
                'unique_attackers': int(row['unique_attackers'])
            }
        
        return timeline_dict
    
    def _analyze_communication_patterns(self, df):
        """Analyze communication patterns"""
        # Convert tuples to strings for JSON serialization
        most_active = df.groupby(['SrcAddr', 'DstAddr']).size().nlargest(10)
        most_active_dict = {f"{src}->{dst}": count for (src, dst), count in most_active.items()}
        
        return {
            'most_active_pairs': most_active_dict,
            'communication_matrix': df.groupby(['LabelCategory', 'ProtoCategory']).size().unstack(fill_value=0).to_dict()
        }
    
    def _analyze_payload_characteristics(self, df):
        """Analyze payload characteristics"""
        return {
            'avg_payload_by_label': df.groupby('LabelCategory')['TotBytes'].mean().to_dict(),
            'payload_size_distribution': df.groupby('LabelCategory')['TotBytes'].describe().to_dict(),
            'packet_size_patterns': df.groupby('LabelCategory')['PktSize'].mean().to_dict()
        }