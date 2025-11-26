"""
CTU-13 Dataset Analysis Tool - Command Line Interface

This module provides a command-line interface for the CTU-13 analysis tool.
"""

import argparse
import logging
import sys
from pathlib import Path
import json

from .downloader import CTU13Downloader
from .parser import CTU13Parser
from .analyzer import CTU13Analyzer
from .visualizer import CTU13Visualizer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CTU13CLI:
    """Command Line Interface for CTU-13 analysis tool"""
    
    def __init__(self):
        self.downloader = CTU13Downloader()
        self.parser = CTU13Parser()
        self.analyzer = CTU13Analyzer()
        self.visualizer = CTU13Visualizer()
    
    def create_parser(self):
        """Create command line argument parser"""
        parser = argparse.ArgumentParser(
            description='CTU-13 Dataset Analysis Tool - Comprehensive cybersecurity analysis',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Download full dataset
  python -m ctu13_analyzer download --full
  
  # Download specific scenarios
  python -m ctu13_analyzer download --scenarios 1 2 3
  
  # Parse and analyze all data
  python -m ctu13_analyzer analyze --all
  
  # Analyze specific scenario
  python -m ctu13_analyzer analyze --scenario 1
  
  # Generate visualizations
  python -m ctu13_analyzer visualize --scenario 1
  
  # Full pipeline
  python -m ctu13_analyzer pipeline --scenarios 1 2 --visualize
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Download command
        download_parser = subparsers.add_parser('download', help='Download CTU-13 dataset')
        download_group = download_parser.add_mutually_exclusive_group(required=True)
        download_group.add_argument('--full', action='store_true', 
                                  help='Download full dataset (1.9GB)')
        download_group.add_argument('--scenarios', nargs='+', type=int, 
                                  choices=range(1, 14), metavar='N',
                                  help='Download specific scenarios (1-13)')
        download_parser.add_argument('--data-dir', default='data/raw',
                                   help='Directory to store downloaded data')
        
        # Parse command
        parse_parser = subparsers.add_parser('parse', help='Parse NetFlow data')
        parse_parser.add_argument('--input-dir', default='data/raw',
                                help='Directory containing .biargus files')
        parse_parser.add_argument('--output-dir', default='data/processed',
                                help='Directory to store processed data')
        parse_parser.add_argument('--scenario', type=int, choices=range(1, 14),
                                help='Parse specific scenario only')
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze network traffic')
        analyze_parser.add_argument('--input-dir', default='data/processed',
                                  help='Directory containing processed data')
        analyze_parser.add_argument('--scenario', type=int, choices=range(1, 14),
                                  help='Analyze specific scenario only')
        analyze_parser.add_argument('--all', action='store_true',
                                  help='Analyze all available scenarios')
        analyze_parser.add_argument('--output-dir', default='data/reports',
                                  help='Directory to store analysis results')
        analyze_parser.add_argument('--anomaly-threshold', type=float, default=0.1,
                                  help='Contamination threshold for anomaly detection')
        
        # Visualize command
        viz_parser = subparsers.add_parser('visualize', help='Generate visualizations')
        viz_parser.add_argument('--input-dir', default='data/processed',
                              help='Directory containing processed data')
        viz_parser.add_argument('--scenario', type=int, choices=range(1, 14),
                              help='Visualize specific scenario only')
        viz_parser.add_argument('--output-dir', default='data/reports',
                              help='Directory to store visualizations')
        viz_parser.add_argument('--interactive', action='store_true',
                              help='Generate interactive visualizations')
        
        # Pipeline command (full workflow)
        pipeline_parser = subparsers.add_parser('pipeline', help='Run complete analysis pipeline')
        pipeline_parser.add_argument('--scenarios', nargs='+', type=int, 
                                   choices=range(1, 14), metavar='N',
                                   help='Scenarios to process (default: all)')
        pipeline_parser.add_argument('--skip-download', action='store_true',
                                   help='Skip download step')
        pipeline_parser.add_argument('--visualize', action='store_true',
                                   help='Generate visualizations')
        pipeline_parser.add_argument('--anomaly-threshold', type=float, default=0.1,
                                   help='Contamination threshold for anomaly detection')
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show dataset information')
        info_parser.add_argument('--scenarios', action='store_true',
                               help='Show scenario information')
        info_parser.add_argument('--files', action='store_true',
                               help='List available files')
        
        return parser
    
    def handle_download(self, args):
        """Handle download command"""
        logger.info("Starting download process...")
        
        self.downloader.data_dir = Path(args.data_dir)
        
        if args.full:
            success = self.downloader.download_full_dataset()
        else:
            success = self.downloader.download_scenarios(args.scenarios)
        
        if success:
            logger.info("Download completed successfully!")
            self.downloader.list_available_files()
        else:
            logger.error("Download failed!")
            return False
        
        return True
    
    def handle_parse(self, args):
        """Handle parse command"""
        logger.info("Starting parsing process...")
        
        self.parser.data_dir = Path(args.input_dir)
        
        if args.scenario:
            # Parse specific scenario
            scenario_file = f"scenario_{args.scenario:02d}_capture.binetflow"
            file_path = self.parser.data_dir / scenario_file
            
            if not file_path.exists():
                logger.error(f"Scenario file not found: {file_path}")
                return False
            
            df = self.parser.parse_biargus_file(file_path)
            if df is not None:
                parsed_data = {f"scenario_{args.scenario:02d}": df}
            else:
                return False
        else:
            # Parse all scenarios
            parsed_data = self.parser.parse_all_scenarios()
            
            if not parsed_data:
                logger.error("No data files found to parse!")
                return False
        
        # Save processed data
        success = self.parser.save_processed_data(parsed_data, args.output_dir)
        
        if success:
            logger.info("Parsing completed successfully!")
        else:
            logger.error("Parsing failed!")
        
        return success
    
    def handle_analyze(self, args):
        """Handle analyze command"""
        logger.info("Starting analysis process...")
        
        input_dir = Path(args.input_dir)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if args.scenario:
            # Analyze specific scenario
            csv_file = input_dir / f"scenario_{args.scenario:02d}_capture_processed.csv"
            if not csv_file.exists():
                logger.error(f"Processed data file not found: {csv_file}")
                return False
            
            scenarios_to_analyze = [args.scenario]
        elif args.all:
            # Find all processed CSV files
            csv_files = list(input_dir.glob("scenario_*_processed.csv"))
            if not csv_files:
                logger.error("No processed data files found!")
                return False
            
            scenarios_to_analyze = [
                int(f.stem.split('_')[1]) for f in csv_files
            ]
        else:
            logger.error("Please specify --scenario N or --all")
            return False
        
        # Analyze each scenario
        all_results = {}
        
        for scenario_num in scenarios_to_analyze:
            logger.info(f"Analyzing scenario {scenario_num}...")
            
            csv_file = input_dir / f"scenario_{scenario_num:02d}_capture_processed.csv"
            
            try:
                import pandas as pd
                df = pd.read_csv(csv_file)
                df['StartTime'] = pd.to_datetime(df['StartTime'])
                
                # Perform analysis
                traffic_analysis = self.analyzer.analyze_traffic_patterns(df)
                df_with_anomalies, anomaly_analysis = self.analyzer.detect_anomalies(
                    df, contamination=args.anomaly_threshold
                )
                botnet_indicators = self.analyzer.detect_botnet_behavior(df)
                df_clustered, cluster_analysis = self.analyzer.cluster_network_behavior(df)
                threat_intel = self.analyzer.generate_threat_intelligence(df)
                
                # Compile results
                scenario_results = {
                    'scenario': scenario_num,
                    'summary': self.parser.get_dataset_summary(df),
                    'traffic_patterns': traffic_analysis,
                    'anomaly_analysis': anomaly_analysis,
                    'botnet_indicators': botnet_indicators,
                    'cluster_analysis': cluster_analysis,
                    'threat_intelligence': threat_intel
                }
                
                all_results[f"scenario_{scenario_num:02d}"] = scenario_results
                
                # Save individual scenario results
                with open(output_dir / f"scenario_{scenario_num:02d}_analysis.json", 'w') as f:
                    json.dump(scenario_results, f, indent=2, default=str)
                
                logger.info(f"Scenario {scenario_num} analysis completed")
                
            except Exception as e:
                logger.error(f"Error analyzing scenario {scenario_num}: {e}")
                continue
        
        # Save combined results
        with open(output_dir / "complete_analysis.json", 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        
        logger.info("Analysis completed successfully!")
        return True
    
    def handle_visualize(self, args):
        """Handle visualize command"""
        logger.info("Starting visualization process...")
        
        input_dir = Path(args.input_dir)
        self.visualizer.output_dir = Path(args.output_dir)
        
        if args.scenario:
            # Try both naming patterns
            csv_file = input_dir / f"scenario_{args.scenario:02d}_processed.csv"
            if not csv_file.exists():
                csv_file = input_dir / f"scenario_{args.scenario:02d}_capture_processed.csv"
            if not csv_file.exists():
                logger.error(f"Processed data file not found for scenario {args.scenario}")
                return False
            
            scenarios_to_viz = [args.scenario]
        else:
            # Find all processed CSV files
            csv_files = list(input_dir.glob("scenario_*_processed.csv"))
            if not csv_files:
                logger.error("No processed data files found!")
                return False
            
            scenarios_to_viz = []
            for f in csv_files:
                # Extract scenario number from filename
                parts = f.stem.split('_')
                if len(parts) >= 2:
                    try:
                        scenario_num = int(parts[1])
                        scenarios_to_viz.append(scenario_num)
                    except ValueError:
                        continue
        
        # Generate visualizations for each scenario
        for scenario_num in scenarios_to_viz:
            logger.info(f"Generating visualizations for scenario {scenario_num}...")
            
            try:
                import pandas as pd
                # Try both naming patterns
                csv_file = input_dir / f"scenario_{scenario_num:02d}_processed.csv"
                if not csv_file.exists():
                    csv_file = input_dir / f"scenario_{scenario_num:02d}_capture_processed.csv"
                
                df = pd.read_csv(csv_file)
                df['StartTime'] = pd.to_datetime(df['StartTime'])
                
                # Load analysis results if available
                analysis_file = Path(args.output_dir) / f"scenario_{scenario_num:02d}_analysis.json"
                if analysis_file.exists():
                    with open(analysis_file, 'r') as f:
                        analysis_results = json.load(f)
                    
                    anomaly_analysis = analysis_results.get('anomaly_analysis', {})
                    botnet_indicators = analysis_results.get('botnet_indicators', {})
                    summary = analysis_results.get('summary', {})
                else:
                    # Run basic analysis for visualization
                    df_with_anomalies, anomaly_analysis = self.analyzer.detect_anomalies(df)
                    botnet_indicators = self.analyzer.detect_botnet_behavior(df)
                    summary = self.parser.get_dataset_summary(df)
                    df = df_with_anomalies
                
                # Generate visualizations
                self.visualizer.save_all_plots(df, summary, anomaly_analysis, botnet_indicators)
                
                logger.info(f"Visualizations for scenario {scenario_num} completed")
                
            except Exception as e:
                logger.error(f"Error generating visualizations for scenario {scenario_num}: {e}")
                continue
        
        logger.info("Visualization process completed!")
        return True
    
    def handle_pipeline(self, args):
        """Handle pipeline command (full workflow)"""
        logger.info("Starting complete analysis pipeline...")
        
        scenarios = args.scenarios if args.scenarios else list(range(1, 14))
        
        # Step 1: Download (if not skipped)
        if not args.skip_download:
            logger.info("Step 1: Downloading data...")
            download_args = argparse.Namespace(
                scenarios=scenarios,
                data_dir='data/raw',
                full=False
            )
            if not self.handle_download(download_args):
                return False
        
        # Step 2: Parse
        logger.info("Step 2: Parsing data...")
        parse_args = argparse.Namespace(
            input_dir='data/raw',
            output_dir='data/processed',
            scenario=None
        )
        if not self.handle_parse(parse_args):
            return False
        
        # Step 3: Analyze
        logger.info("Step 3: Analyzing data...")
        analyze_args = argparse.Namespace(
            input_dir='data/processed',
            output_dir='data/reports',
            scenario=None,
            all=True,
            anomaly_threshold=args.anomaly_threshold
        )
        if not self.handle_analyze(analyze_args):
            return False
        
        # Step 4: Visualize (if requested)
        if args.visualize:
            logger.info("Step 4: Generating visualizations...")
            viz_args = argparse.Namespace(
                input_dir='data/processed',
                output_dir='data/reports',
                scenario=None,
                interactive=True
            )
            if not self.handle_visualize(viz_args):
                return False
        
        logger.info("Complete pipeline finished successfully!")
        return True
    
    def handle_info(self, args):
        """Handle info command"""
        if args.scenarios:
            info = self.downloader.get_scenario_info()
            print("\nCTU-13 Dataset Information:")
            print("=" * 50)
            print(f"Description: {info['description']}")
            print(f"Available Labels: {', '.join(info['labels'])}")
            print(f"File Types: {', '.join(info['file_types'])}")
            print("\nScenarios:")
            for num, name in info['scenarios'].items():
                print(f"  {num:2d}: {name}")
        
        if args.files:
            print("\nAvailable Files:")
            print("=" * 30)
            self.downloader.list_available_files()
        
        return True
    
    def run(self, args=None):
        """Run the CLI application"""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        if not parsed_args.command:
            parser.print_help()
            return False
        
        try:
            if parsed_args.command == 'download':
                return self.handle_download(parsed_args)
            elif parsed_args.command == 'parse':
                return self.handle_parse(parsed_args)
            elif parsed_args.command == 'analyze':
                return self.handle_analyze(parsed_args)
            elif parsed_args.command == 'visualize':
                return self.handle_visualize(parsed_args)
            elif parsed_args.command == 'pipeline':
                return self.handle_pipeline(parsed_args)
            elif parsed_args.command == 'info':
                return self.handle_info(parsed_args)
            else:
                parser.print_help()
                return False
                
        except KeyboardInterrupt:
            logger.info("Operation cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return False

def main():
    """Main entry point"""
    cli = CTU13CLI()
    success = cli.run()
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()