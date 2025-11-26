# CTU-13 Dataset Analysis Tool

A comprehensive cybersecurity analysis tool for the CTU-13 botnet dataset. This tool provides automated downloading, parsing, analysis, and visualization capabilities for network traffic analysis and threat intelligence.

## 🔍 Overview

The CTU-13 dataset contains 13 scenarios of botnet traffic captured at CTU University, Czech Republic, in 2011. Each scenario includes real botnet traffic mixed with normal and background traffic, making it ideal for cybersecurity research and analysis.

## 🚀 Features

- **Automated Dataset Download**: Download complete dataset or specific scenarios
- **NetFlow Parsing**: Parse .biargus NetFlow files with comprehensive data cleaning
- **Advanced Analysis**: 
  - Traffic pattern analysis
  - Anomaly detection using Isolation Forest
  - Botnet behavior detection
  - Network clustering analysis
  - Threat intelligence generation
- **Rich Visualizations**: Interactive and static plots for comprehensive insights
- **Command-Line Interface**: Easy-to-use CLI for all operations
- **Comprehensive Reporting**: JSON and HTML reports with actionable insights

## 📊 Analysis Capabilities

### Traffic Analysis
- Temporal traffic patterns
- Protocol distribution analysis
- Port usage patterns
- IP address analysis
- Flow characteristics

### Security Analysis
- **Anomaly Detection**: Identify unusual network flows
- **Botnet Detection**: 
  - C&C communication patterns
  - Periodic beaconing detection
  - Port scanning activities
  - Data exfiltration detection
  - DNS tunneling detection
- **Threat Intelligence**: Malicious IP identification and attack timelines

### Visualizations
- Traffic overview dashboards
- Security analysis plots
- Interactive timelines
- Network topology visualization
- Botnet behavior dashboards
- Anomaly heatmaps

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Verify Installation
```bash
python main.py info --scenarios
```

## 📖 Usage

### Quick Start
```bash
# Download and analyze scenario 1 with visualizations
python main.py pipeline --scenarios 1 --visualize
```

### Command Reference

#### Download Dataset
```bash
# Download full dataset (1.9GB)
python main.py download --full

# Download specific scenarios
python main.py download --scenarios 1 2 3

# Download to custom directory
python main.py download --scenarios 1 --data-dir /path/to/data
```

#### Parse NetFlow Data
```bash
# Parse all downloaded scenarios
python main.py parse

# Parse specific scenario
python main.py parse --scenario 1

# Custom input/output directories
python main.py parse --input-dir data/raw --output-dir data/processed
```

#### Analyze Traffic
```bash
# Analyze all scenarios
python main.py analyze --all

# Analyze specific scenario
python main.py analyze --scenario 1

# Custom anomaly detection threshold
python main.py analyze --all --anomaly-threshold 0.05
```

#### Generate Visualizations
```bash
# Generate visualizations for all scenarios
python main.py visualize

# Visualize specific scenario
python main.py visualize --scenario 1

# Generate interactive visualizations
python main.py visualize --interactive
```

#### Complete Pipeline
```bash
# Full pipeline for specific scenarios
python main.py pipeline --scenarios 1 2 3 --visualize

# Skip download if data already exists
python main.py pipeline --scenarios 1 --skip-download --visualize

# Custom anomaly threshold
python main.py pipeline --scenarios 1 --anomaly-threshold 0.05 --visualize
```

#### Dataset Information
```bash
# Show scenario information
python main.py info --scenarios

# List available files
python main.py info --files
```

## 📁 Project Structure

```
ctu13_analyzer/
├── ctu13_analyzer/          # Main package
│   ├── __init__.py
│   ├── downloader.py        # Dataset downloading
│   ├── parser.py           # NetFlow parsing
│   ├── analyzer.py         # Traffic analysis
│   ├── visualizer.py       # Visualization generation
│   ├── cli.py              # Command-line interface
│   └── utils.py            # Utility functions
├── data/                   # Data directories
│   ├── raw/               # Downloaded raw data
│   ├── processed/         # Parsed CSV files
│   └── reports/           # Analysis results and visualizations
├── requirements.txt        # Python dependencies
├── main.py                # Main entry point
└── README.md              # This file
```

## 📈 Output Files

### Processed Data
- `scenario_XX_processed.csv`: Parsed and cleaned NetFlow data
- `dataset_summary.csv`: Summary statistics for all scenarios

### Analysis Results
- `scenario_XX_analysis.json`: Detailed analysis results per scenario
- `complete_analysis.json`: Combined analysis results

### Visualizations
- `traffic_overview.png`: Traffic distribution and patterns
- `security_analysis.png`: Security-focused analysis plots
- `anomaly_heatmap.png`: Temporal anomaly distribution
- `interactive_timeline.html`: Interactive traffic timeline
- `network_topology.html`: Network communication visualization
- `botnet_dashboard.html`: Botnet behavior analysis
- `analysis_report.html`: Comprehensive HTML report

## 🔬 Analysis Examples

### Example 1: Basic Traffic Analysis
```bash
# Download and analyze scenario 1
python main.py download --scenarios 1
python main.py parse --scenario 1
python main.py analyze --scenario 1
```

### Example 2: Anomaly Detection
```bash
# Run anomaly detection with custom threshold
python main.py analyze --scenario 1 --anomaly-threshold 0.05
python main.py visualize --scenario 1
```

### Example 3: Multi-Scenario Comparison
```bash
# Compare multiple scenarios
python main.py pipeline --scenarios 1 2 3 --visualize
```

## 📊 Dataset Information

### CTU-13 Scenarios
1. **Scenario 1-13**: Different botnet samples with varying characteristics
2. **Traffic Types**: Botnet, Normal, Background, C&C Channels
3. **Protocols**: TCP, UDP, ICMP
4. **File Formats**: .biargus (bidirectional NetFlow), .pcap (botnet traffic)

### Key Metrics
- **Total Scenarios**: 13
- **Dataset Size**: ~1.9GB (complete)
- **Time Period**: 2011 captures
- **Labels**: Background, Botnet, C&C Channels, Normal

## 🛡️ Security Insights

The tool provides comprehensive cybersecurity insights including:

### Threat Detection
- Malicious IP addresses and domains
- Suspicious port activities
- Unusual traffic patterns
- Command & Control communications

### Attack Patterns
- Botnet communication behaviors
- Data exfiltration attempts
- Port scanning activities
- DNS tunneling detection

### Intelligence Reports
- Attack timelines
- Threat actor profiling
- Network compromise indicators
- Behavioral analysis

## 🔧 Advanced Configuration

### Custom Analysis Parameters
```python
# Example: Custom anomaly detection
analyzer = CTU13Analyzer()
df_with_anomalies, analysis = analyzer.detect_anomalies(
    df, contamination=0.05  # 5% contamination rate
)
```

### Visualization Customization
```python
# Example: Custom visualization settings
visualizer = CTU13Visualizer(output_dir="custom_reports")
visualizer.create_traffic_overview(df, save=True)
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

This project is for educational and research purposes. Please cite the original CTU-13 dataset paper when using this tool:

> Sebastian Garcia, Martin Grill, Jan Stiborek and Alejandro Zunino. "An empirical comparison of botnet detection methods" Computers and Security Journal, Elsevier. 2014. Vol 45, pp 100-123.

## 🆘 Troubleshooting

### Common Issues

1. **Download Failures**
   - Check internet connection
   - Verify dataset URLs are accessible
   - Try downloading individual scenarios

2. **Parsing Errors**
   - Ensure .biargus files are not corrupted
   - Check file permissions
   - Verify sufficient disk space

3. **Memory Issues**
   - Process scenarios individually for large datasets
   - Increase system memory or use sampling

4. **Visualization Problems**
   - Install required visualization libraries
   - Check output directory permissions
   - Verify data format compatibility

### Getting Help
- Check the logs in `logs/` directory
- Use `--help` flag with any command
- Review error messages for specific guidance

## 🎯 Use Cases

- **Cybersecurity Research**: Academic and industry research
- **Threat Hunting**: Identify malicious patterns in network traffic
- **Security Training**: Educational tool for cybersecurity professionals
- **Incident Response**: Analyze network traffic during security incidents
- **Malware Analysis**: Study botnet communication patterns

---

**Happy Analyzing! 🔍🛡️**