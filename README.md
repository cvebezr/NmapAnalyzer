# Nmap Scan Analyzer

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

### Requiements
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
```