import requests
from .base_scanner import BaseScanner

class ReconScanner(BaseScanner):
    def scan(self):
        self.logger.info(f"Starting Reconnaissance on {self.target}...")
        try:
            # Basic connectivity and headers
            if not self.target.startswith("http"):
                url = f"http://{self.target}"
            else:
                url = self.target

            response = requests.get(url, timeout=self.config.get("timeout"))
            
            # Server Info
            server = response.headers.get("Server", "Unknown")
            self.results.append({
                "type": "info",
                "module": "recon",
                "description": f"Server Technology: {server}",
                "severity": "INFO"
            })

            # Security Headers Check
            security_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options"
            ]

            for header in security_headers:
                if header not in response.headers:
                    self.results.append({
                        "type": "vuln",
                        "module": "recon",
                        "description": f"Missing Security Header: {header}",
                        "severity": "LOW"
                    })
                else:
                    self.logger.debug(f"Header found: {header}")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Reconnaissance failed: {e}")
            self.results.append({
                "type": "error",
                "module": "recon",
                "description": f"Connection failed: {str(e)}",
                "severity": "ERROR"
            })
