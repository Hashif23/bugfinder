import json
import os
from tabulate import tabulate

class ReportGenerator:
    def __init__(self, output_file=None):
        self.output_file = output_file

    def generate(self, results):
        if not results:
            print("\n[+] No vulnerabilities found.")
            return

        # Console Output
        print("\n" + "="*60)
        print("SCAN REPORT")
        print("="*60)
        
        table_data = []
        for r in results:
            table_data.append([r.get("type"), r.get("severity"), r.get("description")])

        print(tabulate(table_data, headers=["Type", "Severity", "Description"], tablefmt="grid"))

        # File Output (JSON)
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(results, f, indent=4)
                print(f"\n[+] Report saved to {self.output_file}")
            except Exception as e:
                print(f"\n[-] Error saving report: {e}")
