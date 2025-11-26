"""
Test cases for CTU13Parser module
"""

import unittest
import pandas as pd
import tempfile
import os
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ctu13_analyzer.parser import CTU13Parser


class TestCTU13Parser(unittest.TestCase):
    """Test cases for CTU13Parser"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.parser = CTU13Parser()
        
        # Create sample NetFlow data
        self.sample_netflow_data = [
            "2011/08/10 09:46:53.047277,0.000000,tcp,147.32.84.165,1024,<->,147.32.84.229,6881,SF,0,0,3,120,60,Normal",
            "2011/08/10 09:46:53.047277,5.123456,udp,192.168.1.100,53,<->,8.8.8.8,53,SF,0,0,2,128,64,Background",
            "2011/08/10 09:46:53.047277,1.500000,tcp,10.0.0.1,80,<->,192.168.1.50,12345,SF,0,0,10,1500,750,Botnet",
            "# This is a comment line",
            "2011/08/10 09:46:53.047277,*,icmp,172.16.0.1,*,<->,172.16.0.2,*,SF,0,0,*,*,*,Normal"
        ]
    
    def test_init(self):
        """Test parser initialization"""
        parser = CTU13Parser("test_data")
        self.assertEqual(str(parser.data_dir), "test_data")
        self.assertEqual(len(parser.netflow_columns), 15)
    
    def test_parse_netflow_line_valid(self):
        """Test parsing valid NetFlow lines"""
        line = "2011/08/10 09:46:53.047277,0.000000,tcp,147.32.84.165,1024,<->,147.32.84.229,6881,SF,0,0,3,120,60,Normal"
        result = self.parser._parse_netflow_line(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['StartTime'], "2011/08/10 09:46:53.047277")
        self.assertEqual(result['Dur'], 0.0)
        self.assertEqual(result['Proto'], "tcp")
        self.assertEqual(result['SrcAddr'], "147.32.84.165")
        self.assertEqual(result['TotPkts'], 3)
        self.assertEqual(result['TotBytes'], 120)
        self.assertEqual(result['Label'], "Normal")
    
    def test_parse_netflow_line_with_asterisks(self):
        """Test parsing NetFlow lines with asterisk values"""
        line = "2011/08/10 09:46:53.047277,*,icmp,172.16.0.1,*,<->,172.16.0.2,*,SF,0,0,*,*,*,Normal"
        result = self.parser._parse_netflow_line(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['Dur'], 0.0)
        self.assertEqual(result['TotPkts'], 0)
        self.assertEqual(result['TotBytes'], 0)
        self.assertEqual(result['SrcBytes'], 0)
    
    def test_parse_netflow_line_invalid(self):
        """Test parsing invalid NetFlow lines"""
        # Too few fields
        line = "2011/08/10 09:46:53.047277,0.000000,tcp"
        result = self.parser._parse_netflow_line(line)
        self.assertIsNone(result)
        
        # Invalid numeric values
        line = "2011/08/10 09:46:53.047277,invalid,tcp,147.32.84.165,1024,<->,147.32.84.229,6881,SF,0,0,invalid,120,60,Normal"
        result = self.parser._parse_netflow_line(line)
        self.assertIsNone(result)
    
    def test_extract_port(self):
        """Test port extraction functionality"""
        self.assertEqual(self.parser._extract_port("80"), 80)
        self.assertEqual(self.parser._extract_port("http"), 80)
        self.assertEqual(self.parser._extract_port("https"), 443)
        self.assertEqual(self.parser._extract_port("unknown"), 0)
        self.assertEqual(self.parser._extract_port("*"), 0)
    
    def test_categorize_label(self):
        """Test label categorization"""
        self.assertEqual(self.parser._categorize_label("Normal"), "Normal")
        self.assertEqual(self.parser._categorize_label("Botnet"), "Botnet")
        self.assertEqual(self.parser._categorize_label("C&C"), "C&C")
        self.assertEqual(self.parser._categorize_label("Background"), "Background")
        self.assertEqual(self.parser._categorize_label("Unknown"), "Unknown")
        self.assertEqual(self.parser._categorize_label("SomeOtherLabel"), "Other")
    
    def test_is_private_ip(self):
        """Test private IP detection"""
        self.assertTrue(self.parser._is_private_ip("192.168.1.1"))
        self.assertTrue(self.parser._is_private_ip("10.0.0.1"))
        self.assertTrue(self.parser._is_private_ip("172.16.0.1"))
        self.assertFalse(self.parser._is_private_ip("8.8.8.8"))
        self.assertFalse(self.parser._is_private_ip("147.32.84.165"))
        self.assertFalse(self.parser._is_private_ip("invalid_ip"))
    
    def test_categorize_protocol(self):
        """Test protocol categorization"""
        self.assertEqual(self.parser._categorize_protocol("tcp"), "TCP")
        self.assertEqual(self.parser._categorize_protocol("UDP"), "UDP")
        self.assertEqual(self.parser._categorize_protocol("icmp"), "ICMP")
        self.assertEqual(self.parser._categorize_protocol("unknown"), "Other")
    
    def test_parse_biargus_file(self):
        """Test parsing a complete biargus file"""
        # Create temporary file with sample data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.binetflow', delete=False) as f:
            for line in self.sample_netflow_data:
                f.write(line + '\n')
            temp_file = f.name
        
        try:
            # Parse the file
            df = self.parser.parse_biargus_file(temp_file)
            
            # Verify results
            self.assertIsNotNone(df)
            self.assertIsInstance(df, pd.DataFrame)
            self.assertEqual(len(df), 4)  # 4 valid lines (excluding comment)
            
            # Check columns exist
            expected_columns = ['StartTime', 'Dur', 'Proto', 'SrcAddr', 'DstAddr', 
                              'LabelCategory', 'SrcPort', 'DstPort', 'ProtoCategory']
            for col in expected_columns:
                self.assertIn(col, df.columns)
            
            # Check data types
            self.assertTrue(pd.api.types.is_datetime64_any_dtype(df['StartTime']))
            self.assertTrue(pd.api.types.is_numeric_dtype(df['Dur']))
            self.assertTrue(pd.api.types.is_numeric_dtype(df['TotPkts']))
            
        finally:
            # Clean up
            os.unlink(temp_file)
    
    def test_get_dataset_summary(self):
        """Test dataset summary generation"""
        # Create a simple test DataFrame
        data = {
            'StartTime': pd.to_datetime(['2011-08-10 09:46:53', '2011-08-10 10:46:53']),
            'Dur': [1.0, 2.0],
            'TotPkts': [10, 20],
            'TotBytes': [100, 200],
            'PktSize': [10.0, 10.0],
            'LabelCategory': ['Normal', 'Botnet'],
            'ProtoCategory': ['TCP', 'UDP'],
            'SrcAddr': ['192.168.1.1', '192.168.1.2'],
            'DstAddr': ['8.8.8.8', '8.8.4.4']
        }
        df = pd.DataFrame(data)
        
        summary = self.parser.get_dataset_summary(df)
        
        self.assertEqual(summary['total_flows'], 2)
        self.assertEqual(summary['unique_src_ips'], 2)
        self.assertEqual(summary['unique_dst_ips'], 2)
        self.assertEqual(summary['total_bytes'], 300)
        self.assertEqual(summary['total_packets'], 30)
        self.assertIn('Normal', summary['label_distribution'])
        self.assertIn('Botnet', summary['label_distribution'])
    
    def test_clean_dataframe(self):
        """Test DataFrame cleaning functionality"""
        # Create test data
        data = {
            'StartTime': ['2011/08/10 09:46:53.047277', '2011/08/10 10:46:53.047277'],
            'Dur': [1.0, 2.0],
            'Proto': ['tcp', 'udp'],
            'SrcAddr': ['192.168.1.1', '10.0.0.1'],
            'Sport': ['80', 'http'],
            'DstAddr': ['8.8.8.8', '8.8.4.4'],
            'Dport': ['443', 'https'],
            'TotPkts': [10, 20],
            'TotBytes': [100, 200],
            'SrcBytes': [50, 100],
            'Label': ['Normal', 'Botnet']
        }
        df = pd.DataFrame(data)
        
        cleaned_df = self.parser._clean_dataframe(df)
        
        # Check new columns were added
        expected_new_columns = ['SrcPort', 'DstPort', 'DstBytes', 'PktSize', 
                               'LabelCategory', 'SrcIP_Private', 'DstIP_Private', 'ProtoCategory']
        for col in expected_new_columns:
            self.assertIn(col, cleaned_df.columns)
        
        # Check data transformations
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(cleaned_df['StartTime']))
        self.assertEqual(cleaned_df['SrcPort'].iloc[0], 80)
        self.assertEqual(cleaned_df['DstPort'].iloc[1], 443)
        self.assertTrue(cleaned_df['SrcIP_Private'].iloc[0])  # 192.168.1.1 is private
        self.assertTrue(cleaned_df['SrcIP_Private'].iloc[1])  # 10.0.0.1 is also private


if __name__ == '__main__':
    unittest.main()