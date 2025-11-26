"""
Tests for CTU13Downloader class
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import requests

from ctu13_analyzer.downloader import CTU13Downloader


class TestCTU13Downloader:
    """Test cases for CTU13Downloader"""
    
    @pytest.fixture
    def downloader(self):
        """Create a downloader instance for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            yield CTU13Downloader(data_dir)
    
    def test_init(self, downloader):
        """Test downloader initialization"""
        assert isinstance(downloader.data_dir, Path)
        assert downloader.data_dir.exists()
        assert downloader.base_url == "https://mcfp.felk.cvut.cz/publicDatasets"
        assert len(downloader.scenarios) == 13
    
    def test_get_scenario_info_valid(self, downloader):
        """Test getting scenario info for valid scenario"""
        info = downloader.get_scenario_info(1)
        assert info is not None
        assert 'name' in info
        assert 'description' in info
        assert 'files' in info
        assert info['name'] == 'CTU-Malware-Capture-Botnet-42'
    
    def test_get_scenario_info_invalid(self, downloader):
        """Test getting scenario info for invalid scenario"""
        info = downloader.get_scenario_info(99)
        assert info is None
        
        info = downloader.get_scenario_info(0)
        assert info is None
    
    def test_get_download_url(self, downloader):
        """Test URL generation for downloads"""
        url = downloader._get_download_url(1, 'capture20110810.binetflow')
        expected = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/capture20110810.binetflow"
        assert url == expected
    
    def test_get_local_path(self, downloader):
        """Test local path generation"""
        path = downloader._get_local_path(1, 'capture20110810.binetflow')
        expected = downloader.data_dir / 'raw' / 'scenario_01_capture.binetflow'
        assert path == expected
    
    @patch('requests.get')
    def test_download_file_success(self, mock_get, downloader):
        """Test successful file download"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_content.return_value = [b'test data chunk 1', b'test data chunk 2']
        mock_response.headers = {'content-length': '100'}
        mock_get.return_value = mock_response
        
        url = "http://example.com/test.txt"
        local_path = downloader.data_dir / 'test.txt'
        
        with patch('builtins.open', mock_open()) as mock_file:
            success = downloader._download_file(url, local_path)
            assert success is True
            mock_get.assert_called_once_with(url, stream=True, timeout=30)
            mock_file.assert_called_once_with(local_path, 'wb')
    
    @patch('requests.get')
    def test_download_file_http_error(self, mock_get, downloader):
        """Test file download with HTTP error"""
        mock_get.side_effect = requests.exceptions.HTTPError("404 Not Found")
        
        url = "http://example.com/nonexistent.txt"
        local_path = downloader.data_dir / 'test.txt'
        
        success = downloader._download_file(url, local_path)
        assert success is False
    
    @patch('requests.get')
    def test_download_file_connection_error(self, mock_get, downloader):
        """Test file download with connection error"""
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        url = "http://example.com/test.txt"
        local_path = downloader.data_dir / 'test.txt'
        
        success = downloader._download_file(url, local_path)
        assert success is False
    
    @patch('requests.get')
    def test_download_file_timeout(self, mock_get, downloader):
        """Test file download with timeout"""
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")
        
        url = "http://example.com/test.txt"
        local_path = downloader.data_dir / 'test.txt'
        
        success = downloader._download_file(url, local_path)
        assert success is False
    
    def test_download_scenario_invalid(self, downloader):
        """Test downloading invalid scenario"""
        success = downloader.download_scenario(99)
        assert success is False
    
    @patch.object(CTU13Downloader, '_download_file')
    def test_download_scenario_success(self, mock_download, downloader):
        """Test successful scenario download"""
        mock_download.return_value = True
        
        success = downloader.download_scenario(1)
        assert success is True
        assert mock_download.call_count == 1  # One file for scenario 1
    
    @patch.object(CTU13Downloader, '_download_file')
    def test_download_scenario_partial_failure(self, mock_download, downloader):
        """Test scenario download with some files failing"""
        # First call succeeds, second fails
        mock_download.side_effect = [True, False]
        
        # Use scenario 2 which has 2 files
        success = downloader.download_scenario(2)
        assert success is False  # Should fail if any file fails
        assert mock_download.call_count == 2
    
    @patch.object(CTU13Downloader, 'download_scenario')
    def test_download_scenarios_list(self, mock_download_scenario, downloader):
        """Test downloading multiple scenarios"""
        mock_download_scenario.side_effect = [True, True, False]  # 2 success, 1 failure
        
        scenarios = [1, 2, 3]
        success_count = downloader.download_scenarios(scenarios)
        assert success_count == 2
        assert mock_download_scenario.call_count == 3
    
    @patch.object(CTU13Downloader, 'download_scenario')
    def test_download_all_scenarios(self, mock_download_scenario, downloader):
        """Test downloading all scenarios"""
        # Mock all downloads as successful
        mock_download_scenario.return_value = True
        
        success_count = downloader.download_all()
        assert success_count == 13  # All 13 scenarios
        assert mock_download_scenario.call_count == 13
    
    def test_list_scenarios(self, downloader):
        """Test listing all scenarios"""
        scenarios = downloader.list_scenarios()
        assert len(scenarios) == 13
        assert all('name' in scenario for scenario in scenarios)
        assert all('description' in scenario for scenario in scenarios)
    
    def test_get_download_status(self, downloader):
        """Test getting download status"""
        # Initially, no files should be downloaded
        status = downloader.get_download_status()
        assert len(status) == 13
        assert all(not scenario['downloaded'] for scenario in status)
        
        # Create a fake downloaded file
        scenario_1_file = downloader.data_dir / 'raw' / 'scenario_01_capture.binetflow'
        scenario_1_file.parent.mkdir(parents=True, exist_ok=True)
        scenario_1_file.touch()
        
        status = downloader.get_download_status()
        assert status[0]['downloaded'] is True  # Scenario 1 should be marked as downloaded
        assert all(not scenario['downloaded'] for scenario in status[1:])  # Others should not
    
    def test_cleanup_downloads(self, downloader):
        """Test cleaning up downloaded files"""
        # Create some fake files
        raw_dir = downloader.data_dir / 'raw'
        raw_dir.mkdir(parents=True, exist_ok=True)
        
        test_files = [
            raw_dir / 'scenario_01_capture.binetflow',
            raw_dir / 'scenario_02_capture.binetflow',
            raw_dir / 'scenario_02_detailed.biargus'
        ]
        
        for file_path in test_files:
            file_path.touch()
        
        # Verify files exist
        assert all(f.exists() for f in test_files)
        
        # Clean up
        downloader.cleanup_downloads()
        
        # Verify files are removed
        assert not any(f.exists() for f in test_files)
    
    def test_estimate_download_size(self, downloader):
        """Test download size estimation"""
        # Test single scenario
        size = downloader.estimate_download_size([1])
        assert size > 0
        
        # Test multiple scenarios
        size_multiple = downloader.estimate_download_size([1, 2, 3])
        assert size_multiple > size
        
        # Test all scenarios
        size_all = downloader.estimate_download_size()
        assert size_all > size_multiple
    
    def test_validate_scenario_numbers(self, downloader):
        """Test scenario number validation"""
        # Valid scenarios
        valid = downloader._validate_scenario_numbers([1, 2, 13])
        assert valid == [1, 2, 13]
        
        # Invalid scenarios should be filtered out
        mixed = downloader._validate_scenario_numbers([0, 1, 14, 2, -1])
        assert mixed == [1, 2]
        
        # Empty list
        empty = downloader._validate_scenario_numbers([])
        assert empty == []