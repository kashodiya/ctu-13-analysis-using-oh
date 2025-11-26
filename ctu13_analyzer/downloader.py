"""
CTU-13 Dataset Downloader

This module handles downloading the CTU-13 dataset files from the official sources.
"""

import os
import requests
from tqdm import tqdm
import tarfile
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CTU13Downloader:
    """Downloads CTU-13 dataset files"""
    
    BASE_URL = "https://mcfp.felk.cvut.cz/publicDatasets"
    FULL_DATASET_URL = f"{BASE_URL}/CTU-13-Dataset/CTU-13-Dataset.tar.bz2"
    
    SCENARIOS = {
        1: "CTU-Malware-Capture-Botnet-42",
        2: "CTU-Malware-Capture-Botnet-43", 
        3: "CTU-Malware-Capture-Botnet-44",
        4: "CTU-Malware-Capture-Botnet-45",
        5: "CTU-Malware-Capture-Botnet-46",
        6: "CTU-Malware-Capture-Botnet-47",
        7: "CTU-Malware-Capture-Botnet-48",
        8: "CTU-Malware-Capture-Botnet-49",
        9: "CTU-Malware-Capture-Botnet-50",
        10: "CTU-Malware-Capture-Botnet-51",
        11: "CTU-Malware-Capture-Botnet-52",
        12: "CTU-Malware-Capture-Botnet-53",
        13: "CTU-Malware-Capture-Botnet-54"
    }
    
    def __init__(self, data_dir="data/raw"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def download_file(self, url, filename, chunk_size=8192):
        """Download a file with progress bar"""
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(self.data_dir / filename, 'wb') as file:
                with tqdm(total=total_size, unit='B', unit_scale=True, desc=filename) as pbar:
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if chunk:
                            file.write(chunk)
                            pbar.update(len(chunk))
            
            logger.info(f"Successfully downloaded {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            return False
    
    def download_full_dataset(self):
        """Download the complete CTU-13 dataset (1.9GB)"""
        filename = "CTU-13-Dataset.tar.bz2"
        logger.info("Downloading full CTU-13 dataset...")
        
        if self.download_file(self.FULL_DATASET_URL, filename):
            logger.info("Extracting dataset...")
            self.extract_dataset(filename)
            return True
        return False
    
    def download_scenario(self, scenario_num):
        """Download a specific scenario"""
        if scenario_num not in self.SCENARIOS:
            logger.error(f"Invalid scenario number: {scenario_num}")
            return False
        
        scenario_name = self.SCENARIOS[scenario_num]
        scenario_url = f"{self.BASE_URL}/{scenario_name}/"
        
        logger.info(f"Downloading scenario {scenario_num}: {scenario_name}")
        
        # Download the bidirectional flow file (most important for analysis)
        binetflow_url = f"{scenario_url}capture20110810.binetflow"
        binetflow_filename = f"scenario_{scenario_num:02d}_capture.binetflow"
        
        return self.download_file(binetflow_url, binetflow_filename)
    
    def download_scenarios(self, scenario_list=None):
        """Download multiple scenarios"""
        if scenario_list is None:
            scenario_list = list(self.SCENARIOS.keys())
        
        success_count = 0
        for scenario_num in scenario_list:
            if self.download_scenario(scenario_num):
                success_count += 1
        
        logger.info(f"Successfully downloaded {success_count}/{len(scenario_list)} scenarios")
        return success_count == len(scenario_list)
    
    def extract_dataset(self, filename):
        """Extract the downloaded tar.bz2 file"""
        try:
            filepath = self.data_dir / filename
            with tarfile.open(filepath, 'r:bz2') as tar:
                tar.extractall(path=self.data_dir)
            logger.info("Dataset extracted successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to extract dataset: {e}")
            return False
    
    def list_available_files(self):
        """List all downloaded files"""
        files = list(self.data_dir.glob("*"))
        logger.info(f"Available files in {self.data_dir}:")
        for file in files:
            logger.info(f"  - {file.name} ({file.stat().st_size / (1024*1024):.1f} MB)")
        return files
    
    def get_scenario_info(self):
        """Get information about all scenarios"""
        info = {
            "scenarios": self.SCENARIOS,
            "description": "CTU-13 Dataset contains 13 scenarios of botnet traffic mixed with normal and background traffic",
            "labels": ["Background", "Botnet", "C&C Channels", "Normal"],
            "file_types": [".biargus (bidirectional NetFlow)", ".pcap (botnet traffic only)", "executable files"]
        }
        return info