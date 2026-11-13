# PyHunter - Network Threat Detection Tool

## 1. Project Overview

PyHunter is a Python-based command-line tool designed to analyze network traffic and authentication logs to detect suspicious activities and potential security threats.

The tool supports three input formats:
- PCAP files: network traffic captures.
- Linux auth.log: authentication logs.
- Windows EVTX: Security event logs.

PyHunter detects network attacks, enriches Indicators of Compromise (IOCs) using VirusTotal, and generates JSON and HTML security reports.

## 2. Main Features

- PCAP analysis using Scapy.
- Linux authentication log parsing.
- Windows EVTX event parsing.
- Port scan detection.
- SSH brute-force detection.
- Suspicious DNS detection using Shannon entropy.
- Configurable YAML detection rules.
- MITRE ATT&CK mapping.
- VirusTotal IOC enrichment.
- Local IOC cache and offline mode.
- JSON and HTML reports.
- Automated tests using pytest.

## 3. Project Architecture

PyHunter follows a modular architecture:

- **Ingestion:** Reads PCAP, Linux auth.log and Windows EVTX files.
- **Normalization:** Converts events into a common format.
- **Detection:** Identifies suspicious activities using configurable rules.
- **Enrichment:** Checks IOCs through VirusTotal and a local cache.
- **Reporting:** Generates JSON and HTML security reports.
- **CLI:** Handles command-line arguments and user inputs.

### Project Structure

- app/ingestion/: PCAP, auth.log and EVTX readers.
- app/normalization/: Event normalization.
- app/detection/: Detection engine and YAML rules loader.
- app/enrichment/: VirusTotal integration and IOC cache.
- app/reporting/: JSON and HTML report generators.
- app/cli.py: Command-line arguments.
- app/main.py: Main application.
- rules/: Detection configuration.
- samples/: Synthetic input files.
- tests/: Automated tests.
- reports/: Generated reports.
- scripts/: Utility scripts.
- requirements.txt: Python dependencies.

## 4. Detection Rules and MITRE ATT&CK

PyHunter implements four detection mechanisms:

| Detection | Description | Severity | MITRE ATT&CK |
|---|---|---|---|
| Port Scan | Detects multiple TCP SYN attempts targeting different ports. | HIGH | T1046 |
| SSH Brute Force | Detects repeated failed SSH authentication attempts. | HIGH | T1110 |
| Windows Brute Force | Detects repeated failed Windows logons (Event ID 4625). | HIGH | T1110 |
| Suspicious DNS | Detects DNS queries containing high-entropy domain labels. | MEDIUM | T1071.004 |

Detection parameters are stored in `rules/detection_rules.yaml`.

The configuration allows modification of:
- Detection activation.
- Detection thresholds.
- Time windows.
- Alert severity.
- MITRE ATT&CK technique identifiers.

## 5. Technologies Used

- **Python 3.11:** Main programming language.
- **Scapy:** PCAP file analysis.
- **PyYAML:** YAML configuration loading.
- **python-evtx:** Windows EVTX log parsing.
- **Requests:** VirusTotal API communication.
- **python-dotenv:** Environment variable management.
- **Jinja2:** HTML report generation.
- **pytest:** Automated testing.

## 6. Installation

### Requirements
- Python 3.11
- pip
- Git (optional)

### Setup
1. Clone the repository.
2. Navigate to the PyHunter directory.
3. Create a virtual environment.
4. Activate the virtual environment.
5. Install dependencies using `pip install -r requirements.txt`.

On Windows PowerShell, activate the environment with:

`.venv\Scripts\Activate.ps1`

### VirusTotal Configuration

Create a `.env` file in the project root and add:

`VT_API_KEY=your_virustotal_api_key`

If no API key is configured, PyHunter operates in offline mode.

## 7. Usage

PyHunter is executed from the project root using the Python module interface.

### Display Help

`python -m app.main --help`

### Analyze a PCAP File

`python -m app.main --pcap samples/pcaps/lab_traffic.pcap`

### Analyze a Linux Authentication Log

`python -m app.main --authlog samples/logs/auth.log`

### Analyze Multiple Input Files

`python -m app.main --pcap samples/pcaps/lab_traffic.pcap --authlog samples/logs/auth.log`

### Analyze a Windows EVTX File

`python -m app.main --evtx samples/evtx/Security.evtx`

### Custom Rules and Output Directory

Use `--rules` to specify a custom YAML rules file and `--output` to choose the report directory.

Example:

`python -m app.main --pcap samples/pcaps/lab_traffic.pcap --rules rules/detection_rules.yaml --output reports`

## 8. Generated Reports

After each successful analysis, PyHunter generates two reports in the output directory.

### JSON Report

File: `reports/report.json`

The JSON report contains:
- Total number of detected alerts.
- Alert types.
- Source IP addresses.
- Severity levels.
- Detection details.
- MITRE ATT&CK identifiers.
- IOC enrichment results when available.

### HTML Report

File: `reports/report.html`

The HTML report provides a readable presentation of detected threats, including their types, source IP addresses, severity levels and details.

Both reports are generated automatically after the analysis.

## 9. Automated Tests

PyHunter uses pytest to validate its main components.

Run all tests from the project root:

`python -m pytest -v`

The test suite covers:

- PCAP file ingestion.
- Linux authentication log parsing.
- Windows EVTX event extraction using mocked event data.
- Detection of port scans.
- Detection of SSH brute-force attacks.
- Detection of suspicious DNS queries.
- JSON and HTML report generation.
- IOC cache operations.
- VirusTotal offline mode.

The current test suite contains 34 automated tests.

## 10. Incident Response Procedure

When PyHunter detects a suspicious activity, the security analyst should follow these steps:

1. **Identification:** Review the generated alerts and identify the suspicious source IP, event type and severity.
2. **Validation:** Examine the associated network packets or authentication logs to confirm the suspicious activity.
3. **Investigation:** Analyze the source IP, targeted ports, DNS queries and authentication attempts.
4. **Enrichment:** Check available IOC information using VirusTotal or the local cache.
5. **Containment:** Apply appropriate network security measures manually, such as firewall rules or IP blocking.
6. **Remediation:** Remove the root cause and strengthen the affected security controls.
7. **Recovery:** Restore normal operations and monitor the environment.
8. **Documentation:** Record the incident, investigation findings and actions taken.

PyHunter is a detection and analysis tool. It does not automatically block IP addresses or modify network configurations.

## 11. Ethical Use

PyHunter is designed for educational, research and defensive security purposes.

All tests and demonstrations should be performed using synthetic data or authorized laboratory environments.

Users must have explicit authorization before analyzing network traffic or authentication logs belonging to third parties.

The project must not be used for unauthorized monitoring or malicious activities.

