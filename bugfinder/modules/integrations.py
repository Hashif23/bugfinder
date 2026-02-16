import subprocess
import shutil
from .base_scanner import BaseScanner

class IntegrationScanner(BaseScanner):
    def scan(self):
        self.logger.info("Checking for external tools...")
        
        # Check for Nmap
        if shutil.which("nmap"):
            self.run_nmap()
        else:
            self.logger.warning("Nmap not found. Skipping port scan.")

        # Check for Nikto
        if shutil.which("nikto"):
            self.run_nikto()
        else:
            self.logger.warning("Nikto not found. Skipping web server scan.")

    def run_nmap(self):
        self.logger.info(f"Running Nmap on {self.target}...")
        try:
            # Basic fast scan
            cmd = ["nmap", "-F", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.results.append({
                    "type": "info",
                    "module": "nmap",
                    "description": "Nmap Scan Completed",
                    "severity": "INFO",
                    "raw_output": result.stdout
                })
                if "open" in result.stdout:
                     self.results.append({
                        "type": "vuln",
                        "module": "nmap",
                        "description": "Open ports detected (check raw output)",
                        "severity": "LOW"
                    })
            else:
                self.logger.error(f"Nmap failed: {result.stderr}")

        except Exception as e:
            self.logger.error(f"Error running Nmap: {e}")

    def run_nikto(self):
        self.logger.info(f"Running Nikto on {self.target}...")
        try:
            # Basic Nikto scan (limited to finding headers/outdated software for speed)
            # -h target -Tuning b (Software Identification)
            cmd = ["nikto", "-h", self.target, "-Tuning", "b", "-maxtime", "60"] 
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                 self.results.append({
                    "type": "info",
                    "module": "nikto",
                    "description": "Nikto Scan Completed",
                    "severity": "INFO",
                    "raw_output": result.stdout
                })
            else:
                self.logger.error(f"Nikto failed/timed out: {result.stderr}")

        except Exception as e:
            self.logger.error(f"Error running Nikto: {e}")
