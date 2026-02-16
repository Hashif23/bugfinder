import os
import re
from .base_scanner import BaseScanner

class StaticAnalyzer(BaseScanner):
    def scan(self):
        self.logger.info(f"Starting SAST on {self.target}...")
        
        if os.path.isfile(self.target):
            self.scan_file(self.target)
        elif os.path.isdir(self.target):
            for root, _, files in os.walk(self.target):
                for file in files:
                    if file.endswith(".js"):
                        self.scan_file(os.path.join(root, file))
        else:
             self.logger.warning("Target for SAST must be a file or directory.")

    def scan_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()

            # 1. Dangerous Sinks
            self.check_pattern(file_path, lines, r"eval\(", "Dangerous Function: eval()", "HIGH")
            self.check_pattern(file_path, lines, r"innerHTML\s*=", "DOM XSS Risk: innerHTML assignment", "MEDIUM")
            self.check_pattern(file_path, lines, r"document\.write\(", "Dangerous Function: document.write()", "MEDIUM")
            
            # 2. Hardcoded Secrets (Basic Regex)
            self.check_pattern(file_path, lines, r"(?i)api_key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "Hardcoded API Key", "CRITICAL")
            self.check_pattern(file_path, lines, r"(?i)password\s*[:=]\s*['\"][^'\"]{3,}['\"]", "Possible Hardcoded Password", "HIGH")

            # 3. Logic/Quality
            self.check_pattern(file_path, lines, r"console\.log\(", "Information Leak: console.log found", "LOW")
            self.check_pattern(file_path, lines, r"debugger;", "Debugger statement found", "LOW")

        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")

    def check_pattern(self, file_path, lines, pattern, description, severity):
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                self.results.append({
                    "type": "sast",
                    "module": "static",
                    "description": f"{description} in {os.path.basename(file_path)}:{i+1}",
                    "severity": severity,
                    "file": file_path,
                    "line": i+1,
                    "code": line.strip()
                })
