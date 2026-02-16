# BugFinder

**BugFinder** is a comprehensive terminal-based vulnerability assessment tool designed for cyber security enthusiasts and professionals. It scans for web vulnerabilities, security misconfigurations, and static code analysis issues.

## Features

- **Web Scanning**: Detects XSS, SQL Injection, and CSRF token missing.
- **Reconnaissance**: Checks for security headers and server technology.
- **Static Analysis (SAST)**: Analyzes JavaScript files for dangerous functions and hardcoded secrets.
- **Integrations**: Support for `nmap` and `nikto` wrappers.
- **Interactive Mode**: Easy-to-use wizard for running scans.
- **Reporting**: Generates JSON and Console reports.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Hashif23/bugfinder.git
   cd bugfinder
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   *Note: For external tool integrations, ensure `nmap` and `nikto` are installed on your system (Kali Linux default).*

## Usage

### Run via CLI
```bash
python bugfinder/bugfinder.py -t <TARGET_URL> --scan-type all
```

**Example**:
```bash
python bugfinder/bugfinder.py -t http://testphp.vulnweb.com
```

### Interactive Mode
```bash
python bugfinder/bugfinder.py -i
```

### Scan a Local Directory (SAST)
```bash
python bugfinder/bugfinder.py -t ./src --scan-type sast
```

## detailed Help
```bash
python bugfinder/bugfinder.py --help
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
