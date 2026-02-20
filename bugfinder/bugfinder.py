import argparse
import sys
import os

# Ensure the current directory is in the path to import local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import logging
from config import Config
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description="BugFinder - A Comprehensive Terminal-Based Vulnerability Detection Tool")
    parser.add_argument("-t", "--target", help="Target URL or File Path (for SAST)", required=False) # Not required for interactive mode
    parser.add_argument("-i", "--interactive", action="store_true", help="Enable Interactive Mode")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--scan-type", help="Specific scan type (all, xss, sqli, headers, sast)", default="all")
    
    args = parser.parse_args()

    # Initialize Config
    cfg = Config(args.config)
    
    # Initialize Logger
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(level=log_level)
    logger.info("Initializing BugFinder...")

    target = args.target

    if args.interactive:
        logger.info("Starting Interactive Mode...")
        
        if not target:
            target = input("Enter target URL or Path: ").strip()
        
        print("\nAvailable Scan Types:")
        print("1. All (Recon, Web, SAST, Integrations)")
        print("2. Recon (Headers, Server Info)")
        print("3. Web Vulns (XSS, SQLi)")
        print("4. SAST (Static Analysis for JS)")
        print("5. External Tools (Nmap, Nikto)")
        
        choice = input("Select Scan Type (1-5) [Default: 1]: ").strip()
        
        scan_map = {
            "1": "all",
            "2": "recon",
            "3": "web",
            "4": "sast",
            "5": "integration"
        }
        
        args.scan_type = scan_map.get(choice, "all")
        print(f"Selected Scan Type: {args.scan_type}")

        save_choice = input("Save this configuration? (y/n): ").strip().lower()
        if save_choice == 'y':
            cfg_name = input("Enter config filename (e.g., config.json): ").strip()
            cfg.set("target", target)
            cfg.set("default_scan", args.scan_type)
            cfg.save_config(cfg_name)
            print(f"Configuration saved to {cfg_name}")

    if not target:
        logger.error("No target specified. Use -t or --interactive.")
        parser.print_help()
        sys.exit(1)

    logger.info(f"Target: {target}")
    logger.info(f"Scan Type: {args.scan_type}")
    from modules.reconnaissance import ReconScanner
    from modules.web_vulns import WebVulnScanner
    from modules.static_analyzer import StaticAnalyzer
    from modules.integrations import IntegrationScanner
    from utils.report_gen import ReportGenerator

    all_results = []

    # Reconnaissance
    if args.scan_type in ["all", "recon", "headers"]:
        recon = ReconScanner(target, cfg, logger)
        recon.scan()
        all_results.extend(recon.get_results())

    # Web Vulnerabilities
    if args.scan_type in ["all", "web", "xss", "sqli"]:
        web = WebVulnScanner(target, cfg, logger)
        web.scan()
        all_results.extend(web.get_results())

    # Static Analysis
    if args.scan_type in ["all", "sast", "static"]:
        sast = StaticAnalyzer(target, cfg, logger)
        sast.scan()
        all_results.extend(sast.get_results())

    # Integrations (External Tools)
    if args.scan_type in ["all", "integration", "nmap"]:
        integ = IntegrationScanner(target, cfg, logger)
        integ.scan()
        all_results.extend(integ.get_results())

    # Report Generation
    reporter = ReportGenerator(args.output)
    reporter.generate(all_results)
    
    logger.info("Scan complete.")

if __name__ == "__main__":
    main()
