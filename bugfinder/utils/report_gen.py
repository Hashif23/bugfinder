import json
import os
import time
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_file=None):
        self.output_file = output_file

    def generate(self, results):
        if not results:
            print("\n[+] No vulnerabilities found.")
            return

        # --- Console Output ---
        print("\n" + "="*60)
        print("BUG FINDER - SCAN REPORT")
        print("="*60)
        
        # 1. Executive Summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in results:
            sev = r.get("severity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1 # Default bucket

        print("\n[+] Executive Summary")
        print(f"    Total Findings: {len(results)}")
        print("    Severities:")
        for sev, count in severity_counts.items():
            if count > 0:
                print(f"      - {sev}: {count}")

        # 2. Detailed Findings
        print("\n[+] Detailed Findings")
        
        # Group by Module to keep it organized
        results_by_module = {}
        for r in results:
            mod = r.get("module", "General")
            if mod not in results_by_module:
                results_by_module[mod] = []
            results_by_module[mod].append(r)

        for mod, module_results in results_by_module.items():
            print(f"\n--- Module: {mod.upper()} ---")
            for i, r in enumerate(module_results, 1):
                severity = r.get("severity", "INFO")
                description = r.get("description", "No description")
                
                # Color code severity (simulated with text for now, real terminal colors would require colorama)
                print(f"\n[{i}] {severity} - {description}")
                
                # Context/Location
                if "file" in r and "line" in r:
                     print(f"    Location: {r['file']}:{r['line']}")
                elif "url" in r: # Some web scanners might add this
                     print(f"    URL: {r['url']}")
                
                # Code Snippet (SAST)
                if "code" in r:
                    print(f"    Code: {r['code'].strip()}")
                
                # Raw Output (Nmap/Nikto)
                if "raw_output" in r:
                    print(f"    Raw Output (Snippet): {r['raw_output'][:200]}...")


        # --- File Output (JSON) ---
        if self.output_file:
            report_data = {
                "scan_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tool": "BugFinder",
                    "version": "1.0"
                },
                "summary": severity_counts,
                "results": results
            }
            
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(report_data, f, indent=4)
                print(f"\n[+] Detailed report saved to {self.output_file}")
            except Exception as e:
                print(f"\n[-] Error saving report: {e}")
