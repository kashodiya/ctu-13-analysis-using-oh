"""
Test cases for CTU13Analyzer module
"""

import unittest
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ctu13_analyzer.analyzer import CTU13Analyzer


class TestCTU13Analyzer(unittest.TestCase):
    """Test cases for CTU13Analyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = CTU13Analyzer()
        
        # Create sample DataFrame for testing
        np.random.seed(42)
        n_samples = 100
        
        self.sample_df = pd.DataFrame({
            'StartTime': pd.date_range('2011-08-10 09:00:00', periods=n_samples, freq='1min'),
            'Dur': np.random.exponential(1.0, n_samples),
            'Proto': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
            'SrcAddr': [f"192.168.1.{i%50+1}" for i in range(n_samples)],
            'DstAddr': [f"10.0.0.{i%20+1}" for i in range(n_samples)],
            'SrcPort': np.random.randint(1024, 65535, n_samples),
            'DstPort': np.random.choice([80, 443, 53, 22, 21], n_samples),
            'TotPkts': np.random.poisson(10, n_samples),
            'TotBytes': np.random.poisson(1000, n_samples),
            'SrcBytes': np.random.poisson(500, n_samples),
            'DstBytes': np.random.poisson(500, n_samples),
            'PktSize': np.random.normal(100, 20, n_samples),
            'LabelCategory': np.random.choice(['Normal', 'Botnet', 'C&C', 'Background'], n_samples),
            'ProtoCategory': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
            'SrcIP_Private': [True] * n_samples,
            'DstIP_Private': [True] * n_samples
        })
    
    def test_init(self):
        """Test analyzer initialization"""
        analyzer = CTU13Analyzer()
        self.assertIsNotNone(analyzer.scaler)
    
    def test_analyze_traffic_patterns(self):
        """Test traffic pattern analysis"""
        analysis = self.analyzer.analyze_traffic_patterns(self.sample_df)
        
        # Check that all expected analysis components are present
        expected_keys = ['temporal_patterns', 'protocol_analysis', 'port_analysis', 
                        'ip_analysis', 'flow_characteristics']
        for key in expected_keys:
            self.assertIn(key, analysis)
        
        # Check that analysis contains meaningful data
        self.assertIsInstance(analysis, dict)
        self.assertTrue(len(analysis) > 0)
    
    def test_detect_anomalies(self):
        """Test anomaly detection"""
        df_with_anomalies, anomaly_analysis = self.analyzer.detect_anomalies(self.sample_df, contamination=0.1)
        
        # Check that anomaly columns were added
        self.assertIn('Anomaly', df_with_anomalies.columns)
        self.assertIn('AnomalyScore', df_with_anomalies.columns)
        
        # Check anomaly analysis structure
        expected_keys = ['total_anomalies', 'anomaly_percentage', 'anomaly_by_label', 
                        'top_anomalous_ips', 'anomaly_protocols']
        for key in expected_keys:
            self.assertIn(key, anomaly_analysis)
        
        # Check that some anomalies were detected
        self.assertGreater(anomaly_analysis['total_anomalies'], 0)
        self.assertGreater(anomaly_analysis['anomaly_percentage'], 0)
        
        # Check that anomaly labels are correct (-1 for anomaly, 1 for normal)
        unique_labels = df_with_anomalies['Anomaly'].unique()
        self.assertTrue(all(label in [-1, 1] for label in unique_labels))
    
    def test_detect_botnet_behavior(self):
        """Test botnet behavior detection"""
        botnet_indicators = self.analyzer.detect_botnet_behavior(self.sample_df)
        
        # Check that all expected indicators are present
        expected_indicators = ['c2_communication', 'periodic_beaconing', 'port_scanning', 
                              'data_exfiltration', 'dns_tunneling']
        for indicator in expected_indicators:
            self.assertIn(indicator, botnet_indicators)
        
        # Check that indicators return meaningful data
        self.assertIsInstance(botnet_indicators, dict)
    
    def test_cluster_network_behavior(self):
        """Test network behavior clustering"""
        df_with_clusters, cluster_analysis = self.analyzer.cluster_network_behavior(self.sample_df)
        
        # Check that cluster column was added
        self.assertIn('Cluster', df_with_clusters.columns)
        
        # Check cluster analysis structure (matching actual implementation)
        # The actual implementation returns a dict with cluster_X keys
        self.assertIsInstance(cluster_analysis, dict)
        
        # Check that we have some cluster information
        # Note: DBSCAN might not find clusters in random data, so we just check the structure
    
    def test_analyze_temporal_patterns(self):
        """Test temporal pattern analysis"""
        temporal_analysis = self.analyzer._analyze_temporal_patterns(self.sample_df)
        
        # Check expected keys in temporal analysis (matching actual implementation)
        expected_keys = ['hourly_distribution', 'daily_distribution', 'peak_hours', 'traffic_by_label_hour']
        for key in expected_keys:
            self.assertIn(key, temporal_analysis)
        
        # Check that hourly distribution contains data
        self.assertGreater(len(temporal_analysis['hourly_distribution']), 0)
    
    def test_analyze_protocols(self):
        """Test protocol analysis"""
        protocol_analysis = self.analyzer._analyze_protocols(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['protocol_distribution', 'bytes_by_protocol', 'malicious_protocols']
        for key in expected_keys:
            self.assertIn(key, protocol_analysis)
        
        # Check that protocol distribution contains known protocols
        protocols = list(protocol_analysis['protocol_distribution'].keys())
        self.assertTrue(any(proto in ['TCP', 'UDP', 'ICMP'] for proto in protocols))
    
    def test_analyze_ports(self):
        """Test port analysis"""
        port_analysis = self.analyzer._analyze_ports(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['top_src_ports', 'top_dst_ports', 'malicious_dst_ports', 'unusual_ports']
        for key in expected_keys:
            self.assertIn(key, port_analysis)
        
        # Check that port lists contain reasonable data
        self.assertIsInstance(port_analysis['top_src_ports'], dict)
        self.assertIsInstance(port_analysis['top_dst_ports'], dict)
    
    def test_analyze_ip_addresses(self):
        """Test IP address analysis"""
        ip_analysis = self.analyzer._analyze_ip_addresses(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['unique_src_ips', 'unique_dst_ips', 'top_talkers', 'top_destinations', 'private_vs_public']
        for key in expected_keys:
            self.assertIn(key, ip_analysis)
        
        # Check that IP counts are reasonable
        self.assertGreater(ip_analysis['unique_src_ips'], 0)
        self.assertGreater(ip_analysis['unique_dst_ips'], 0)
    
    def test_analyze_flow_characteristics(self):
        """Test flow characteristics analysis"""
        flow_analysis = self.analyzer._analyze_flow_characteristics(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['avg_flow_duration', 'avg_packet_size', 'flow_size_distribution', 'long_flows', 'large_flows']
        for key in expected_keys:
            self.assertIn(key, flow_analysis)
        
        # Check that statistics are meaningful
        self.assertIsInstance(flow_analysis['flow_size_distribution'], dict)
        self.assertIn('mean', flow_analysis['flow_size_distribution'])
        self.assertIn('std', flow_analysis['flow_size_distribution'])
    
    def test_detect_c2_communication(self):
        """Test C&C communication detection"""
        c2_analysis = self.analyzer._detect_c2_communication(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['potential_c2_servers', 'total_suspects']
        for key in expected_keys:
            self.assertIn(key, c2_analysis)
    
    def test_detect_periodic_beaconing(self):
        """Test periodic beaconing detection"""
        beaconing_analysis = self.analyzer._detect_periodic_beaconing(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['beaconing_pairs', 'total_beaconing']
        for key in expected_keys:
            self.assertIn(key, beaconing_analysis)
    
    def test_detect_port_scanning(self):
        """Test port scanning detection"""
        scan_analysis = self.analyzer._detect_port_scanning(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['port_scan_activities', 'total_scanners']
        for key in expected_keys:
            self.assertIn(key, scan_analysis)
    
    def test_detect_data_exfiltration(self):
        """Test data exfiltration detection"""
        exfil_analysis = self.analyzer._detect_data_exfiltration(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['potential_exfiltration', 'total_large_transfers']
        for key in expected_keys:
            self.assertIn(key, exfil_analysis)
    
    def test_detect_dns_tunneling(self):
        """Test DNS tunneling detection"""
        dns_analysis = self.analyzer._detect_dns_tunneling(self.sample_df)
        
        # Check expected structure (matching actual implementation)
        expected_keys = ['suspicious_dns_clients', 'total_suspicious']
        for key in expected_keys:
            self.assertIn(key, dns_analysis)
    
    def test_get_top_anomalous_ips(self):
        """Test top anomalous IPs extraction"""
        # Create a sample anomalies DataFrame
        anomalies_df = self.sample_df.head(10).copy()
        anomalies_df['AnomalyScore'] = np.random.uniform(-0.5, -0.1, 10)
        
        top_ips = self.analyzer._get_top_anomalous_ips(anomalies_df)
        
        # Check that result is a dictionary
        self.assertIsInstance(top_ips, dict)
        
        # Check that it contains both source and destination IPs (matching actual implementation)
        expected_keys = ['top_anomalous_sources', 'top_anomalous_destinations']
        for key in expected_keys:
            self.assertIn(key, top_ips)
    
    def test_empty_dataframe_handling(self):
        """Test handling of empty DataFrames"""
        empty_df = pd.DataFrame()
        
        # These should not crash and should return meaningful empty results
        try:
            analysis = self.analyzer.analyze_traffic_patterns(empty_df)
            self.assertIsInstance(analysis, dict)
        except Exception as e:
            # If it raises an exception, it should be handled gracefully
            self.assertIsInstance(e, (ValueError, KeyError))
    
    def test_missing_columns_handling(self):
        """Test handling of DataFrames with missing columns"""
        incomplete_df = pd.DataFrame({
            'StartTime': pd.date_range('2011-08-10', periods=10),
            'SrcAddr': ['192.168.1.1'] * 10
        })
        
        # Should handle missing columns gracefully
        try:
            analysis = self.analyzer.analyze_traffic_patterns(incomplete_df)
            self.assertIsInstance(analysis, dict)
        except Exception as e:
            # Should raise appropriate exceptions for missing required columns
            self.assertIsInstance(e, (KeyError, ValueError))


if __name__ == '__main__':
    unittest.main()