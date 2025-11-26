"""
CTU-13 Dataset Analysis Tool - Utility Functions

This module provides utility functions for the CTU-13 analysis tool.
"""

import logging
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)

def setup_logging(level=logging.INFO, log_file=None):
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if log_file:
        logging.basicConfig(
            level=level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(level=level, format=log_format)

def validate_ip_address(ip_str):
    """Validate IP address format"""
    try:
        import ipaddress
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def calculate_file_hash(filepath):
    """Calculate MD5 hash of a file"""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {filepath}: {e}")
        return None

def save_json_report(data, filepath, indent=2):
    """Save data as JSON report with proper formatting"""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=indent, default=str, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Error saving JSON report to {filepath}: {e}")
        return False

def load_json_report(filepath):
    """Load JSON report from file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON report from {filepath}: {e}")
        return None

def format_bytes(bytes_value):
    """Format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def format_duration(seconds):
    """Format duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    else:
        return f"{seconds/86400:.2f} days"

def create_directory_structure(base_dir):
    """Create the required directory structure"""
    base_path = Path(base_dir)
    
    directories = [
        'data/raw',
        'data/processed', 
        'data/reports',
        'logs'
    ]
    
    for directory in directories:
        dir_path = base_path / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {dir_path}")
    
    return True

def get_system_info():
    """Get system information for reporting"""
    import platform
    import psutil
    
    return {
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'cpu_count': psutil.cpu_count(),
        'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
        'timestamp': datetime.now().isoformat()
    }

def validate_scenario_number(scenario_num):
    """Validate scenario number is in valid range"""
    return isinstance(scenario_num, int) and 1 <= scenario_num <= 13

def get_scenario_filename(scenario_num, file_type='biargus'):
    """Get standardized filename for scenario"""
    if not validate_scenario_number(scenario_num):
        raise ValueError(f"Invalid scenario number: {scenario_num}")
    
    if file_type == 'biargus':
        return f"scenario_{scenario_num:02d}_capture.biargus"
    elif file_type == 'processed':
        return f"scenario_{scenario_num:02d}_processed.csv"
    elif file_type == 'analysis':
        return f"scenario_{scenario_num:02d}_analysis.json"
    else:
        raise ValueError(f"Unknown file type: {file_type}")

def merge_dataframes(df_list, scenario_labels=None):
    """Merge multiple scenario dataframes with scenario labels"""
    if not df_list:
        return None
    
    if scenario_labels and len(scenario_labels) != len(df_list):
        raise ValueError("Number of scenario labels must match number of dataframes")
    
    merged_dfs = []
    for i, df in enumerate(df_list):
        df_copy = df.copy()
        if scenario_labels:
            df_copy['Scenario'] = scenario_labels[i]
        else:
            df_copy['Scenario'] = f"scenario_{i+1:02d}"
        merged_dfs.append(df_copy)
    
    return pd.concat(merged_dfs, ignore_index=True)

def filter_timerange(df, start_time=None, end_time=None):
    """Filter dataframe by time range"""
    if 'StartTime' not in df.columns:
        logger.warning("StartTime column not found in dataframe")
        return df
    
    filtered_df = df.copy()
    
    if start_time:
        filtered_df = filtered_df[filtered_df['StartTime'] >= start_time]
    
    if end_time:
        filtered_df = filtered_df[filtered_df['StartTime'] <= end_time]
    
    return filtered_df

def get_top_talkers(df, n=10, by='TotBytes'):
    """Get top N communicating hosts"""
    if by not in df.columns:
        logger.error(f"Column {by} not found in dataframe")
        return None
    
    src_talkers = df.groupby('SrcAddr')[by].sum().nlargest(n)
    dst_talkers = df.groupby('DstAddr')[by].sum().nlargest(n)
    
    return {
        'top_sources': src_talkers.to_dict(),
        'top_destinations': dst_talkers.to_dict()
    }

def calculate_entropy(data_series):
    """Calculate Shannon entropy of a data series"""
    import numpy as np
    
    value_counts = data_series.value_counts()
    probabilities = value_counts / len(data_series)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    
    return entropy

def detect_outliers_iqr(data_series, multiplier=1.5):
    """Detect outliers using Interquartile Range method"""
    Q1 = data_series.quantile(0.25)
    Q3 = data_series.quantile(0.75)
    IQR = Q3 - Q1
    
    lower_bound = Q1 - multiplier * IQR
    upper_bound = Q3 + multiplier * IQR
    
    outliers = data_series[(data_series < lower_bound) | (data_series > upper_bound)]
    
    return {
        'outlier_indices': outliers.index.tolist(),
        'outlier_values': outliers.tolist(),
        'bounds': {'lower': lower_bound, 'upper': upper_bound},
        'outlier_count': len(outliers)
    }

def generate_summary_stats(df, columns=None):
    """Generate comprehensive summary statistics"""
    if columns is None:
        numeric_columns = df.select_dtypes(include=['number']).columns
    else:
        numeric_columns = [col for col in columns if col in df.columns]
    
    summary = {}
    
    for col in numeric_columns:
        summary[col] = {
            'count': df[col].count(),
            'mean': df[col].mean(),
            'std': df[col].std(),
            'min': df[col].min(),
            'max': df[col].max(),
            'median': df[col].median(),
            'q25': df[col].quantile(0.25),
            'q75': df[col].quantile(0.75),
            'entropy': calculate_entropy(df[col]),
            'outliers': detect_outliers_iqr(df[col])
        }
    
    return summary

class ProgressTracker:
    """Simple progress tracking utility"""
    
    def __init__(self, total_steps, description="Processing"):
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.start_time = datetime.now()
    
    def update(self, step_description=None):
        """Update progress"""
        self.current_step += 1
        progress = (self.current_step / self.total_steps) * 100
        
        elapsed = datetime.now() - self.start_time
        
        if step_description:
            logger.info(f"{self.description}: {step_description} ({progress:.1f}% complete)")
        else:
            logger.info(f"{self.description}: Step {self.current_step}/{self.total_steps} ({progress:.1f}% complete)")
    
    def finish(self):
        """Mark as finished"""
        elapsed = datetime.now() - self.start_time
        logger.info(f"{self.description} completed in {elapsed.total_seconds():.2f} seconds")

def create_config_template():
    """Create a configuration template"""
    config = {
        'data_directories': {
            'raw': 'data/raw',
            'processed': 'data/processed',
            'reports': 'data/reports'
        },
        'analysis_settings': {
            'anomaly_threshold': 0.1,
            'clustering_eps': 0.5,
            'clustering_min_samples': 5
        },
        'visualization_settings': {
            'figure_size': [12, 8],
            'dpi': 300,
            'style': 'seaborn-v0_8'
        },
        'logging': {
            'level': 'INFO',
            'log_file': 'logs/ctu13_analysis.log'
        }
    }
    
    return config