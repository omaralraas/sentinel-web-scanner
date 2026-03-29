# Sentinel Web Scanner 🛡️

Sentinel is a modular, CLI-based modern web vulnerability scanner written in Python. It is designed to automatically check target URLs for security misconfigurations, missing headers, and common web flaws like unauthenticated IDORs.

## Features

- **Modular Architecture**: Built to be easily extensible. Drop new Python scripts into the `modules/` folder and they become instantly available.
- **Header Analysis**: Checks for missing or misconfigured `HSTS`, `Content-Security-Policy (CSP)`, `X-Frame-Options`, and detects server version leakage.
- **API Discovery & Fuzzing**: Probes for common API endpoints and fuzzes integer IDs to discover **Insecure Direct Object Reference (IDOR)** vulnerabilities.
- **Reporting**: Automatically exports scan results to timestamped JSON files.
- **Discord Alerting**: Seamless native Discord Webhook integration for real-time alerting on High/Critical findings.
- **Mock Lab Included**: Ships with an intentionally vulnerable Flask application (`test_lab.py`) so you can test the scanner immediately.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinel-web-scanner.git
cd sentinel-web-scanner

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Settings, target URLs, and webhook configurations are managed in `config.yaml`:

```yaml
target: "http://127.0.0.1:5000"
discord_webhook: "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
scan_settings:
  default_timeout: 5
  max_idor_ids: 5
```

## Usage

You can run the scanner using the CLI attributes or rely entirely on your `config.yaml`.

```bash
# Run using the settings defined in config.yaml
python scanner.py

# Override the target URL via CLI
python scanner.py --target http://example.com

# Explicitly choose which modules to run
python scanner.py --target http://127.0.0.1:5000 --modules header_analyzer api_fuzzer

# Run in verbose mode for debugging
python scanner.py --verbose
```

## Testing with the Mock Lab

Sentinel includes a deliberately vulnerable Flask application for testing:

1. Open a terminal and start the lab:
   ```bash
   python test_lab.py
   ```
2. Open a second terminal and run Sentinel:
   ```bash
   python scanner.py
   ```
3. Check the `reports/` directory for the generated JSON report proving the vulnerabilities were detected.

## Adding Custom Modules

Creating a new module is simple. Add a Python file in `modules/` that exposes a `run(target, config)` function returning a list of dictionaries:

```python
# modules/my_custom_module.py

def run(target: str, config: dict) -> list[dict]:
    # perform checks...
    return [{
        "module": "my_custom_module",
        "severity": "High",
        "title": "Vulnerability Found",
        "detail": "Explanation here",
        "evidence": "Payload or HTTP response"
    }]
```

## License
MIT License.
