# phishing-url-sandbox-analyzer
Python tool to analyze phishing URLs and extract IOCs using Virus Total API
# Phishing URL Sandbox Analyzer in Python

This project is a Python-based cybersecurity tool that analyzes suspicious URLs using the VirusTotal API and extracts Indicators of Compromise (IOCs).

## Features
- Submits URLs to VirusTotal for malware scanning
- Retrieves scan reports automatically
- Extracts malicious IPs and domains (when available)
- Handles API rate limits
- Supports bulk URL scanning from a file
- Exports results to JSON

## How to Run

1. Install dependencies:

2. Add your VirusTotal API key in `config.py`

3. Add URLs in `urls.txt`

4. Run:

## Output
Results are saved in `sample_output.json`

