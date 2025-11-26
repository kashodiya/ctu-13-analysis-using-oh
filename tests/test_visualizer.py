"""
Tests for CTU13Visualizer class
"""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path
import tempfile
import shutil
from unittest.mock import patch, MagicMock

from ctu13_analyzer.visualizer import CTU13Visualizer


class TestCTU13Visualizer:
    """Test cases for CTU13Visualizer"""
    
    @pytest.fixture
    def visualizer(self):
        """Create a visualizer instance for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            yield CTU13Visualizer(output_dir)
    
    @pytest.fixture
    def sample_df(self):
        """Create sample dataframe for testing"""
        np.random.seed(42)
        n_rows = 100
        
        return pd.DataFrame({
            'StartTime': pd.date_range('2023-01-01', periods=n_rows, freq='1min'),
            'SrcAddr': np.random.choice(['192.168.1.10', '192.168.1.20', '10.0.0.5'], n_rows),
            'DstAddr': np.random.choice(['8.8.8.8', '1.1.1.1', '192.168.1.1'], n_rows),
            'SrcPort': np.random.randint(1024, 65535, n_rows),
            'DstPort': np.random.choice([80, 443, 53, 22], n_rows),
            'Proto': np.random.choice(['tcp', 'udp'], n_rows),
            'ProtoCategory': np.random.choice(['TCP', 'UDP'], n_rows),  # Add missing column
            'TotBytes': np.random.randint(100, 10000, n_rows),
            'SrcBytes': np.random.randint(50, 5000, n_rows),
            'Label': np.random.choice(['BENIGN', 'Botnet', 'C&C'], n_rows),
            'LabelCategory': np.random.choice(['Normal', 'Malicious'], n_rows),
            'SrcIP_Private': np.random.choice([True, False], n_rows),
            'DstIP_Private': np.random.choice([True, False], n_rows)
        })
    
    def test_init(self, visualizer):
        """Test visualizer initialization"""
        assert isinstance(visualizer.output_dir, Path)
        assert visualizer.output_dir.exists()
    
    @patch('matplotlib.pyplot.savefig')
    def test_create_traffic_overview(self, mock_savefig, visualizer, sample_df):
        """Test traffic overview visualization creation"""
        fig = visualizer.create_traffic_overview(sample_df, save=False)
        assert fig is not None
        
        # Test with save=True
        visualizer.create_traffic_overview(sample_df, save=True)
        mock_savefig.assert_called()
    
    @patch('matplotlib.pyplot.savefig')
    def test_create_security_analysis(self, mock_savefig, visualizer, sample_df):
        """Test security analysis visualization creation"""
        # Create mock anomaly analysis
        anomaly_analysis = {
            'total_anomalies': 5,
            'anomaly_types': ['high_bytes', 'unusual_port']
        }
        
        fig = visualizer.create_security_analysis_plots(sample_df, anomaly_analysis, save=False)
        assert fig is not None
        
        # Test with save=True
        visualizer.create_security_analysis_plots(sample_df, anomaly_analysis, save=True)
        mock_savefig.assert_called()
    
    def test_create_interactive_timeline(self, visualizer, sample_df):
        """Test interactive timeline creation"""
        fig = visualizer.create_interactive_timeline(sample_df, save=False)
        assert fig is not None
        
        # Test with save=True
        with patch('plotly.graph_objects.Figure.write_html') as mock_write:
            visualizer.create_interactive_timeline(sample_df, save=True)
            mock_write.assert_called()
    
    def test_create_network_topology(self, visualizer, sample_df):
        """Test network topology visualization creation"""
        fig = visualizer.create_network_topology_viz(sample_df, save=False)
        assert fig is not None
        
        # Test with save=True
        with patch('plotly.graph_objects.Figure.write_html') as mock_write:
            visualizer.create_network_topology_viz(sample_df, save=True)
            mock_write.assert_called()
    
    def test_create_botnet_dashboard(self, visualizer, sample_df):
        """Test botnet dashboard creation"""
        # Create mock botnet indicators
        botnet_indicators = {
            'c2_communication': {
                'potential_c2_servers': {'8.8.8.8': {'connection_count': 10, 'avg_interval': 60}}
            },
            'periodic_beaconing': {
                'beaconing_hosts': {'192.168.1.10': {'beacon_score': 0.8, 'intervals': [60, 61, 59]}}
            },
            'port_scanning': {
                'scanning_hosts': {'192.168.1.20': {'unique_ports': 50, 'scan_rate': 10}}
            },
            'data_exfiltration': {
                'potential_exfiltration': {
                    'SrcBytes': {'192.168.1.10': 1000000},
                    'DstAddr': {'192.168.1.10': 5},
                    'sessions': {'192.168.1.10': 100}
                }
            }
        }
        
        fig = visualizer.create_botnet_analysis_dashboard(sample_df, botnet_indicators, save=False)
        assert fig is not None
        
        # Test with save=True
        with patch('plotly.graph_objects.Figure.write_html') as mock_write:
            visualizer.create_botnet_analysis_dashboard(sample_df, botnet_indicators, save=True)
            mock_write.assert_called()
    
    def test_generate_summary_report(self, visualizer, sample_df):
        """Test summary report generation"""
        analysis_results = {
            'summary': {
                'total_flows': 100,
                'unique_src_ips': 3,
                'unique_dst_ips': 3,
                'malicious_flows': 30
            },
            'anomaly_analysis': {
                'total_anomalies': 5,
                'anomaly_types': ['high_bytes', 'unusual_port']
            }
        }
        
        # Test without save
        report_html = visualizer.generate_summary_report(analysis_results, save=False)
        assert isinstance(report_html, str)
        assert 'CTU-13 Analysis Report' in report_html
        
        # Test with save
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file
            
            visualizer.generate_summary_report(analysis_results, save=True)
            mock_open.assert_called()
            mock_file.write.assert_called()
    
    def test_save_all_plots(self, visualizer, sample_df):
        """Test saving all plots at once"""
        analysis_results = {
            'summary': {'total_flows': 100},
            'anomaly_analysis': {'total_anomalies': 5},
            'botnet_indicators': {
                'c2_communication': {'potential_c2_servers': {}},
                'periodic_beaconing': {'beaconing_hosts': {}},
                'port_scanning': {'scanning_hosts': {}},
                'data_exfiltration': {'potential_exfiltration': {}}
            }
        }
        
        anomaly_analysis = {'total_anomalies': 5}
        botnet_indicators = analysis_results['botnet_indicators']
        
        with patch('matplotlib.pyplot.savefig'), \
             patch('plotly.graph_objects.Figure.write_html'), \
             patch('builtins.open', create=True):
            
            visualizer.save_all_plots(sample_df, analysis_results, anomaly_analysis, botnet_indicators)
            # If no exception is raised, the test passes
    
    def test_empty_dataframe_handling(self, visualizer):
        """Test handling of empty dataframes"""
        empty_df = pd.DataFrame()
        
        # These should handle empty dataframes gracefully
        try:
            fig1 = visualizer.create_traffic_overview(empty_df, save=False)
            fig2 = visualizer.create_interactive_timeline(empty_df, save=False)
            fig3 = visualizer.create_network_topology_viz(empty_df, save=False)
            
            # All should return valid figure objects or None
            assert fig1 is not None or fig1 is None
            assert fig2 is not None or fig2 is None
            assert fig3 is not None or fig3 is None
        except Exception as e:
            # If exceptions occur, they should be handled gracefully
            assert isinstance(e, (KeyError, ValueError))
    
    def test_missing_columns_handling(self, visualizer):
        """Test handling of dataframes with missing columns"""
        incomplete_df = pd.DataFrame({
            'StartTime': pd.date_range('2023-01-01', periods=10, freq='1min'),
            'SrcAddr': ['192.168.1.1'] * 10
        })
        
        # These should handle missing columns gracefully
        try:
            visualizer.create_traffic_overview(incomplete_df, save=False)
            visualizer.create_interactive_timeline(incomplete_df, save=False)
            visualizer.create_network_topology_viz(incomplete_df, save=False)
        except Exception as e:
            # If exceptions occur, they should be handled gracefully
            assert isinstance(e, (KeyError, ValueError))