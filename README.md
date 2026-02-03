# NmapAnalyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![GitHub stars](https://img.shields.io/github/stars/cvebezr/NmapAnalyzer.svg)](https://github.com/cvebezr/NmapAnalyzer/stargazers)

**Automated Nmap scanner with intelligent reporting, service classification, and HTML report generation.**

## Features

✅ **Automated Scanning** - One-command network scanning with custom Nmap arguments  
✅ **Smart Service Classification** - Automatic port categorization by service type  
✅ **Multiple Report Formats** - Text, HTML, and XML outputs  
✅ **Comprehensive Logging** - Detailed operation logs with timestamps  
✅ **Large Network Support** - Optimized for /16, /8 network scans  
✅ **Flexible Configuration** - Customizable scanning parameters  
✅ **Ethical by Default** - Non-intrusive scanning presets  
✅ **Professional Reports** - Clean HTML reports with visual categorization  

## Quick Start

### Hot to install
```bash
#Clone from git
git clone https://github.com/cvebezr/NmapAnalyzer
```

### Requirements
```bash
# Ubuntu/Debian
sudo apt-get install nmap xsltproc python3

# CentOS/RHEL
sudo yum install nmap libxslt python3

# macOS
brew install nmap libxslt
```
### How to use
```bash
sudo chmod +x ./NmapAnalyzer.py

#Scanning with default settings
./NmapAnalyzer.py 192.168.0.2 -D report 

#Scanning with other NMAP scanning settings
./NmapAnalyzer.py 192.168.0.2 -n "-sC -p-" -D report 

#Scanning /24, /16, /8 networks
./NmapAnalyzer.py 192.168.1.0/24 -D report
./NmapAnalyzer.py 192.168.0.0/16 -D report 
./NmapAnalyzer.py 192.0.0.0/8 -D report

#Scanning multiple networks
./NmapAnalyzer.py 192.168-255.0-255.0-255 -D report
```

## Legal Disclaimer

**IMPORTANT: LEGAL AND ETHICAL USE ONLY**

### Legal Compliance
This tool is intended for **AUTHORIZED SECURITY TESTING ONLY**. You must:
- Only scan networks you own or have explicit written permission to test
- Comply with all applicable laws (CFAA, Computer Misuse Act, etc.)
- Obtain proper authorization before any scanning activity

### Prohibited Uses
**STRICTLY FORBIDDEN**:
- Unauthorized network scanning
- Testing systems without permission
- Any illegal or malicious activities
- Privacy violations

### No Warranty & Liability
**THE SOFTWARE IS PROVIDED "AS IS"**, WITHOUT WARRANTY OF ANY KIND. 

**THE AUTHOR ASSUMES NO RESPONSIBILITY** for:
- Misuse or illegal activities with this software
- Damages from software use
- Legal consequences of unauthorized scanning
- Any law violations by users

**YOU ARE SOLELY RESPONSIBLE** for ensuring your activities are legal and authorized.

### Professional Recommendations
- Obtain proper certifications (CEH, OSCP, etc.)
- Always have written authorization
- Maintain documentation of testing activities
- Follow established ethical guidelines

### Reporting Security Issues
Report vulnerabilities responsibly to appropriate parties, not publicly.

**USE THIS TOOL RESPONSIBLY AND LEGALLY.**
