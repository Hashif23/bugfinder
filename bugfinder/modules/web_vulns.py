import requests
from .base_scanner import BaseScanner

class WebVulnScanner(BaseScanner):
    def scan(self):
        self.logger.info(f"Starting Web Vulnerability Scan on {self.target}...")
        if not self.target.startswith("http"):
             url = f"http://{self.target}"
        else:
             url = self.target

        self.scan_xss(url)
        self.scan_sqli(url)
        # self.scan_csrf(url) # Requires more complex parsing, skipping for MVP basic

    def scan_xss(self, url):
        # Very basic reflected XSS check
        payload = "<script>alert('XSS')</script>"
        try:
            # Check if URL has parameters
            if "?" in url:
                target_url = f"{url}&test={payload}"
                resp = requests.get(target_url, timeout=self.config.get("timeout"))
                if payload in resp.text:
                    self.results.append({
                        "type": "vuln",
                        "module": "web",
                        "description": f"Reflected XSS Vulnerability detected at {target_url}",
                        "severity": "HIGH"
                    })
        except Exception as e:
            self.logger.error(f"XSS Scan Error: {e}")

    def scan_sqli(self, url):
        # Basic SQLi check
        payload = "'"
        try:
            if "?" in url:
                target_url = f"{url}&id={payload}"
                resp = requests.get(target_url, timeout=self.config.get("timeout"))
                
                sql_errors = [
                    "you have an error in your sql syntax",
                    "mysql_fetch",
                    "sqlstate",
                    "postgresql",
                    "unclosed quotation mark"
                ]
                
                for error in sql_errors:
                    if error in resp.text.lower():
                        self.results.append({
                            "type": "vuln",
                            "module": "web",
                            "description": f"Possible SQL Injection vulnerability detected at {target_url}",
                            "severity": "CRITICAL"
                        })
                        break
        except Exception as e:
            self.logger.error(f"SQLi Scan Error: {e}")
