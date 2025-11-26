"""
CTU-13 Dataset Visualizer

This module provides visualization capabilities for network traffic analysis.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CTU13Visualizer:
    """Visualization tools for CTU-13 dataset analysis"""
    
    def __init__(self, output_dir="data/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def create_traffic_overview(self, df, save=True):
        """Create overview visualizations of network traffic"""
        logger.info("Creating traffic overview visualizations...")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('CTU-13 Network Traffic Overview', fontsize=16, fontweight='bold')
        
        # 1. Label distribution
        label_counts = df['LabelCategory'].value_counts()
        axes[0, 0].pie(label_counts.values, labels=label_counts.index, autopct='%1.1f%%')
        axes[0, 0].set_title('Traffic Label Distribution')
        
        # 2. Protocol distribution
        proto_counts = df['ProtoCategory'].value_counts()
        axes[0, 1].bar(proto_counts.index, proto_counts.values)
        axes[0, 1].set_title('Protocol Distribution')
        axes[0, 1].set_ylabel('Number of Flows')
        
        # 3. Hourly traffic pattern
        df['Hour'] = df['StartTime'].dt.hour
        hourly_traffic = df.groupby('Hour')['TotBytes'].sum() / 1e6  # Convert to MB
        axes[1, 0].plot(hourly_traffic.index, hourly_traffic.values, marker='o')
        axes[1, 0].set_title('Hourly Traffic Volume')
        axes[1, 0].set_xlabel('Hour of Day')
        axes[1, 0].set_ylabel('Traffic Volume (MB)')
        axes[1, 0].grid(True, alpha=0.3)
        
        # 4. Flow size distribution
        axes[1, 1].hist(np.log10(df['TotBytes'].replace(0, 1)), bins=50, alpha=0.7)
        axes[1, 1].set_title('Flow Size Distribution (Log Scale)')
        axes[1, 1].set_xlabel('Log10(Bytes)')
        axes[1, 1].set_ylabel('Frequency')
        
        plt.tight_layout()
        
        if save:
            plt.savefig(self.output_dir / 'traffic_overview.png', dpi=300, bbox_inches='tight')
            logger.info(f"Saved traffic overview to {self.output_dir / 'traffic_overview.png'}")
        
        return fig
    
    def create_security_analysis_plots(self, df, anomaly_analysis, save=True):
        """Create security-focused analysis plots"""
        logger.info("Creating security analysis visualizations...")
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('CTU-13 Security Analysis', fontsize=16, fontweight='bold')
        
        # 1. Anomaly distribution by label
        if 'anomaly_by_label' in anomaly_analysis:
            anomaly_labels = list(anomaly_analysis['anomaly_by_label'].keys())
            anomaly_counts = list(anomaly_analysis['anomaly_by_label'].values())
            axes[0, 0].bar(anomaly_labels, anomaly_counts, color='red', alpha=0.7)
            axes[0, 0].set_title('Anomalies by Traffic Label')
            axes[0, 0].set_ylabel('Number of Anomalies')
            axes[0, 0].tick_params(axis='x', rotation=45)
        
        # 2. Top malicious destination ports
        malicious_flows = df[df['LabelCategory'].isin(['Botnet', 'C&C'])]
        if len(malicious_flows) > 0:
            top_ports = malicious_flows['DstPort'].value_counts().head(10)
            axes[0, 1].barh(range(len(top_ports)), top_ports.values)
            axes[0, 1].set_yticks(range(len(top_ports)))
            axes[0, 1].set_yticklabels(top_ports.index)
            axes[0, 1].set_title('Top Malicious Destination Ports')
            axes[0, 1].set_xlabel('Number of Flows')
        
        # 3. Traffic volume by label over time
        df['TimeWindow'] = df['StartTime'].dt.floor('h')
        traffic_by_time = df.groupby(['TimeWindow', 'LabelCategory'])['TotBytes'].sum().unstack(fill_value=0)
        
        for label in traffic_by_time.columns:
            axes[0, 2].plot(traffic_by_time.index, traffic_by_time[label] / 1e6, 
                          label=label, marker='o', markersize=3)
        axes[0, 2].set_title('Traffic Volume Over Time by Label')
        axes[0, 2].set_ylabel('Traffic Volume (MB)')
        axes[0, 2].legend()
        axes[0, 2].tick_params(axis='x', rotation=45)
        
        # 4. Flow duration vs bytes scatter (colored by label)
        sample_df = df.sample(min(5000, len(df)))  # Sample for performance
        for label in sample_df['LabelCategory'].unique():
            label_data = sample_df[sample_df['LabelCategory'] == label]
            axes[1, 0].scatter(label_data['Dur'], label_data['TotBytes'], 
                             label=label, alpha=0.6, s=10)
        axes[1, 0].set_xlabel('Flow Duration (seconds)')
        axes[1, 0].set_ylabel('Total Bytes')
        axes[1, 0].set_title('Flow Duration vs Size')
        axes[1, 0].set_yscale('log')
        axes[1, 0].legend()
        
        # 5. Protocol usage by label
        proto_label = df.groupby(['ProtoCategory', 'LabelCategory']).size().unstack(fill_value=0)
        proto_label.plot(kind='bar', stacked=True, ax=axes[1, 1])
        axes[1, 1].set_title('Protocol Usage by Traffic Label')
        axes[1, 1].set_ylabel('Number of Flows')
        axes[1, 1].tick_params(axis='x', rotation=45)
        axes[1, 1].legend(title='Label')
        
        # 6. Packet size distribution by label
        for label in df['LabelCategory'].unique():
            label_data = df[df['LabelCategory'] == label]['PktSize']
            axes[1, 2].hist(label_data, bins=30, alpha=0.5, label=label, density=True)
        axes[1, 2].set_xlabel('Average Packet Size (bytes)')
        axes[1, 2].set_ylabel('Density')
        axes[1, 2].set_title('Packet Size Distribution by Label')
        axes[1, 2].legend()
        axes[1, 2].set_xlim(0, 2000)  # Focus on reasonable packet sizes
        
        plt.tight_layout()
        
        if save:
            plt.savefig(self.output_dir / 'security_analysis.png', dpi=300, bbox_inches='tight')
            logger.info(f"Saved security analysis to {self.output_dir / 'security_analysis.png'}")
        
        return fig
    
    def create_interactive_timeline(self, df, save=True):
        """Create interactive timeline visualization"""
        logger.info("Creating interactive timeline...")
        
        # Prepare data
        df['TimeWindow'] = df['StartTime'].dt.floor('10min')  # 10-minute windows
        timeline_data = df.groupby(['TimeWindow', 'LabelCategory']).agg({
            'TotBytes': 'sum',
            'StartTime': 'count'
        }).rename(columns={'StartTime': 'FlowCount'}).reset_index()
        
        # Create interactive plot
        fig = px.line(timeline_data, x='TimeWindow', y='TotBytes', 
                     color='LabelCategory', 
                     title='Network Traffic Timeline',
                     labels={'TotBytes': 'Total Bytes', 'TimeWindow': 'Time'})
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Total Bytes",
            hovermode='x unified'
        )
        
        if save:
            fig.write_html(self.output_dir / 'interactive_timeline.html')
            logger.info(f"Saved interactive timeline to {self.output_dir / 'interactive_timeline.html'}")
        
        return fig
    
    def create_network_topology_viz(self, df, top_n=50, save=True):
        """Create network topology visualization"""
        logger.info("Creating network topology visualization...")
        
        # Get top communicating pairs
        comm_pairs = df.groupby(['SrcAddr', 'DstAddr']).agg({
            'TotBytes': 'sum',
            'StartTime': 'count',
            'LabelCategory': lambda x: x.mode().iloc[0] if not x.mode().empty else 'Unknown'
        }).rename(columns={'StartTime': 'FlowCount'}).reset_index()
        
        top_pairs = comm_pairs.nlargest(top_n, 'TotBytes')
        
        # Create network graph visualization
        fig = go.Figure()
        
        # Add edges (connections)
        for _, row in top_pairs.iterrows():
            fig.add_trace(go.Scatter(
                x=[hash(row['SrcAddr']) % 1000, hash(row['DstAddr']) % 1000],
                y=[hash(row['SrcAddr']) % 1000, hash(row['DstAddr']) % 1000],
                mode='lines',
                line=dict(width=np.log10(row['TotBytes'])/2, color='gray'),
                hoverinfo='none',
                showlegend=False
            ))
        
        # Add nodes
        all_ips = set(top_pairs['SrcAddr'].tolist() + top_pairs['DstAddr'].tolist())
        
        for ip in all_ips:
            ip_data = df[df['SrcAddr'] == ip]
            if len(ip_data) == 0:
                ip_data = df[df['DstAddr'] == ip]
            
            dominant_label = ip_data['LabelCategory'].mode().iloc[0] if not ip_data['LabelCategory'].mode().empty else 'Unknown'
            
            fig.add_trace(go.Scatter(
                x=[hash(ip) % 1000],
                y=[hash(ip) % 1000],
                mode='markers',
                marker=dict(
                    size=10,
                    color=self._get_color_for_label(dominant_label)
                ),
                text=f"{ip}<br>Label: {dominant_label}",
                hoverinfo='text',
                name=dominant_label,
                showlegend=True
            ))
        
        fig.update_layout(
            title="Network Communication Topology (Top Connections)",
            showlegend=True,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        
        if save:
            fig.write_html(self.output_dir / 'network_topology.html')
            logger.info(f"Saved network topology to {self.output_dir / 'network_topology.html'}")
        
        return fig
    
    def create_botnet_analysis_dashboard(self, df, botnet_indicators, save=True):
        """Create comprehensive botnet analysis dashboard"""
        logger.info("Creating botnet analysis dashboard...")
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('C&C Communication Patterns', 'Beaconing Detection',
                          'Port Scanning Activities', 'Data Exfiltration Patterns'),
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # 1. C&C Communication
        if 'c2_communication' in botnet_indicators and botnet_indicators['c2_communication']['total_suspects'] > 0:
            c2_data = botnet_indicators['c2_communication']['potential_c2_servers']
            c2_ips = list(c2_data.keys())[:10]  # Top 10
            c2_frequencies = [c2_data[ip]['frequency'] for ip in c2_ips]
            
            fig.add_trace(
                go.Bar(x=c2_ips, y=c2_frequencies, name='C&C Frequency'),
                row=1, col=1
            )
        
        # 2. Beaconing patterns
        if 'periodic_beaconing' in botnet_indicators and botnet_indicators['periodic_beaconing']['total_beaconing'] > 0:
            beaconing_data = botnet_indicators['periodic_beaconing']['beaconing_pairs'][:10]
            beacon_pairs = [f"{b['src'][:8]}...→{b['dst'][:8]}..." for b in beaconing_data]
            beacon_intervals = [b['avg_interval'] for b in beaconing_data]
            
            fig.add_trace(
                go.Bar(x=beacon_pairs, y=beacon_intervals, name='Beacon Interval'),
                row=1, col=2
            )
        
        # 3. Port scanning
        if 'port_scanning' in botnet_indicators and botnet_indicators['port_scanning']['total_scanners'] > 0:
            scan_data = botnet_indicators['port_scanning']['port_scan_activities']
            scan_pairs = list(scan_data.keys())[:10]
            scan_ports = [scan_data[pair]['unique_ports'] for pair in scan_pairs]
            
            fig.add_trace(
                go.Bar(x=[f"{pair[:15]}..." if len(pair) > 15 else pair for pair in scan_pairs], 
                      y=scan_ports, name='Unique Ports'),
                row=2, col=1
            )
        
        # 4. Data exfiltration
        if 'data_exfiltration' in botnet_indicators:
            exfil_data = botnet_indicators['data_exfiltration']['potential_exfiltration']
            if exfil_data and 'SrcBytes' in exfil_data:
                exfil_ips = list(exfil_data['SrcBytes'].keys())[:10]
                exfil_bytes = [exfil_data['SrcBytes'][ip] / 1e6 for ip in exfil_ips]  # Convert to MB
                
                fig.add_trace(
                    go.Bar(x=exfil_ips, y=exfil_bytes, name='Data Sent (MB)'),
                    row=2, col=2
                )
        
        fig.update_layout(
            title_text="Botnet Behavior Analysis Dashboard",
            showlegend=False,
            height=800
        )
        
        if save:
            fig.write_html(self.output_dir / 'botnet_dashboard.html')
            logger.info(f"Saved botnet dashboard to {self.output_dir / 'botnet_dashboard.html'}")
        
        return fig
    
    def create_anomaly_heatmap(self, df_with_anomalies, save=True):
        """Create heatmap of anomalies"""
        logger.info("Creating anomaly heatmap...")
        
        # Create time-based heatmap
        df_with_anomalies['Hour'] = df_with_anomalies['StartTime'].dt.hour
        df_with_anomalies['DayOfWeek'] = df_with_anomalies['StartTime'].dt.day_name()
        
        # Count anomalies by hour and day
        anomaly_heatmap = df_with_anomalies[df_with_anomalies['Anomaly'] == -1].groupby(
            ['DayOfWeek', 'Hour']
        ).size().unstack(fill_value=0)
        
        # Reorder days
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        anomaly_heatmap = anomaly_heatmap.reindex(day_order)
        
        plt.figure(figsize=(12, 6))
        sns.heatmap(anomaly_heatmap, annot=True, fmt='d', cmap='Reds', 
                   cbar_kws={'label': 'Number of Anomalies'})
        plt.title('Anomaly Detection Heatmap (by Day and Hour)')
        plt.xlabel('Hour of Day')
        plt.ylabel('Day of Week')
        
        if save:
            plt.savefig(self.output_dir / 'anomaly_heatmap.png', dpi=300, bbox_inches='tight')
            logger.info(f"Saved anomaly heatmap to {self.output_dir / 'anomaly_heatmap.png'}")
        
        return plt.gcf()
    
    def generate_summary_report(self, analysis_results, save=True):
        """Generate a comprehensive summary report"""
        logger.info("Generating summary report...")
        
        report_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CTU-13 Dataset Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #ecf0f1; border-radius: 5px; }}
                .alert {{ background-color: #e74c3c; color: white; padding: 10px; border-radius: 5px; }}
                .warning {{ background-color: #f39c12; color: white; padding: 10px; border-radius: 5px; }}
                .success {{ background-color: #27ae60; color: white; padding: 10px; border-radius: 5px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>CTU-13 Dataset Analysis Report</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This report provides a comprehensive analysis of the CTU-13 botnet dataset, 
                including traffic patterns, anomaly detection, and cybersecurity insights.</p>
            </div>
            
            <div class="section">
                <h2>Dataset Overview</h2>
                <div class="metric">
                    <strong>Total Flows:</strong> {analysis_results.get('total_flows', 'N/A')}
                </div>
                <div class="metric">
                    <strong>Analysis Period:</strong> {analysis_results.get('time_range', {}).get('duration_hours', 'N/A'):.1f} hours
                </div>
                <div class="metric">
                    <strong>Unique Source IPs:</strong> {analysis_results.get('unique_src_ips', 'N/A')}
                </div>
                <div class="metric">
                    <strong>Unique Destination IPs:</strong> {analysis_results.get('unique_dst_ips', 'N/A')}
                </div>
            </div>
            
            <div class="section">
                <h2>Security Findings</h2>
                <div class="alert">
                    <strong>High Priority:</strong> Botnet activity detected in dataset
                </div>
                <div class="warning">
                    <strong>Medium Priority:</strong> Anomalous traffic patterns identified
                </div>
                <div class="success">
                    <strong>Info:</strong> Analysis completed successfully
                </div>
            </div>
            
            <div class="section">
                <h2>Key Metrics</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Total Traffic Volume</td><td>{analysis_results.get('total_bytes', 0) / 1e9:.2f} GB</td></tr>
                    <tr><td>Average Flow Duration</td><td>{analysis_results.get('avg_flow_duration', 0):.2f} seconds</td></tr>
                    <tr><td>Average Packet Size</td><td>{analysis_results.get('avg_packet_size', 0):.2f} bytes</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    <li>Monitor identified malicious IP addresses</li>
                    <li>Implement network segmentation for infected hosts</li>
                    <li>Deploy intrusion detection systems for identified attack patterns</li>
                    <li>Regular monitoring of unusual port activities</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        if save:
            with open(self.output_dir / 'analysis_report.html', 'w') as f:
                f.write(report_html)
            logger.info(f"Saved summary report to {self.output_dir / 'analysis_report.html'}")
        
        return report_html
    
    def _get_color_for_label(self, label):
        """Get color for traffic label"""
        color_map = {
            'Botnet': 'red',
            'C&C': 'darkred',
            'Normal': 'green',
            'Background': 'blue',
            'Unknown': 'gray'
        }
        return color_map.get(label, 'gray')
    
    def save_all_plots(self, df, analysis_results, anomaly_analysis, botnet_indicators):
        """Save all visualization plots"""
        logger.info("Saving all visualization plots...")
        
        # Create all visualizations
        self.create_traffic_overview(df, save=True)
        self.create_security_analysis_plots(df, anomaly_analysis, save=True)
        self.create_interactive_timeline(df, save=True)
        self.create_network_topology_viz(df, save=True)
        self.create_botnet_analysis_dashboard(df, botnet_indicators, save=True)
        
        if 'Anomaly' in df.columns:
            self.create_anomaly_heatmap(df, save=True)
        
        self.generate_summary_report(analysis_results, save=True)
        
        logger.info(f"All visualizations saved to {self.output_dir}")
        
        return True