#!/usr/bin/env python3
"""
Nmap Scan Analyzer
Automates Nmap scanning with results analysis and report generation
"""

import argparse
import sys
import os
import re
import subprocess
import logging
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from collections import defaultdict
import shutil
import time
import threading
import queue
import ipaddress

class Color:
    """Colors"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def validate_ip_address(ip_str):
    """Validate IPv4 address format"""
    pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = pattern.match(ip_str)
    if not match:
        return False
    
    # Check each octet is between 0-255
    for octet in match.groups():
        if not (0 <= int(octet) <= 255):
            return False
    
    return True

def validate_ip_range(ip_range):
    """Validate IP range format (e.g., 192.168.1.1-100)"""
    if '-' not in ip_range:
        return False
    
    # Check if it's a simple range like 192.168.1.1-100
    if ip_range.count('.') == 3 and ip_range.count('-') == 1:
        parts = ip_range.split('-')
        if len(parts) != 2:
            return False
        
        ip_part = parts[0]
        range_part = parts[1]
        
        # Validate IP part
        if not validate_ip_address(ip_part):
            return False
        
        # Validate range part
        try:
            range_num = int(range_part)
            if not (1 <= range_num <= 254):
                return False
        except ValueError:
            return False
        
        return True
    
    # Check if it's a multi-range like 192.168.0-100.0-100
    return validate_multi_range(ip_range)

def validate_multi_range(multi_range):
    """Validate multi-range format like 192.168.0-100.0-100"""
    parts = multi_range.split('.')
    if len(parts) != 4:
        return False
    
    octet_pattern = re.compile(r'^(\d{1,3})(?:-(\d{1,3}))?$')
    
    for octet_str in parts:
        match = octet_pattern.match(octet_str)
        if not match:
            return False
        
        start_str = match.group(1)
        end_str = match.group(2)
        
        try:
            start = int(start_str)
            if not (0 <= start <= 255):
                return False
            
            if end_str:
                end = int(end_str)
                if not (0 <= end <= 255):
                    return False
                if start > end:
                    return False
        except ValueError:
            return False
    
    return True

def expand_multi_range(multi_range):
    """Expand multi-range like 192.168.0-100.0-100 to individual IPs"""
    parts = multi_range.split('.')
    expanded_ranges = []
    
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            expanded_ranges.append(list(range(start, end + 1)))
        else:
            expanded_ranges.append([int(part)])
    
    # Generate all combinations
    from itertools import product
    ips = []
    for combination in product(*expanded_ranges):
        ip = '.'.join(map(str, combination))
        ips.append(ip)
    
    return ips

def calculate_hosts_count(target, target_type):
    """Calculate number of hosts for different target types"""
    if target_type == "cidr":
        parts = target.split('/')
        mask = int(parts[1])
        total_hosts = 2 ** (32 - mask)
        if mask <= 30:
            total_hosts -= 2
        return total_hosts
    
    elif target_type == "ip_range":
        parts = target.split('-')
        ip_base = parts[0]
        range_end = int(parts[1])
        ip_parts = ip_base.split('.')
        if len(ip_parts) == 4:
            try:
                start_octet = int(ip_parts[3])
                total_hosts = range_end - start_octet + 1
                return total_hosts if total_hosts > 0 else None
            except ValueError:
                return None
        return None
    
    elif target_type == "multi_range":
        try:
            ips = expand_multi_range(target)
            return len(ips)
        except:
            return None
    
    elif target_type in ["single_ip", "domain"]:
        return 1
    
    return None

def validate_cidr(cidr_str):
    """Validate CIDR notation"""
    if '/' not in cidr_str:
        return False
    
    parts = cidr_str.split('/')
    if len(parts) != 2:
        return False
    
    ip_part = parts[0]
    mask_part = parts[1]
    
    # Validate IP part
    if not validate_ip_address(ip_part):
        return False
    
    # Validate mask part
    try:
        mask = int(mask_part)
        if not (0 <= mask <= 32):
            return False
    except ValueError:
        return False
    
    return True

def validate_target(target):
    """Validate scan target"""
    # Check if it's a domain name (basic check)
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        return True, "domain"
    
    # Check if it's a single IP
    if validate_ip_address(target):
        return True, "single_ip"
    
    # Check if it's an IP range (simple or multi)
    if validate_ip_range(target):
        # Determine type
        if '-' in target and target.count('.') == 3 and target.count('-') == 1:
            # Check if it's simple range
            parts = target.split('-')
            if '.' in parts[0] and not '.' in parts[1]:
                return True, "ip_range"
        # It's a multi-range
        return True, "multi_range"
    
    # Check if it's CIDR notation
    if validate_cidr(target):
        return True, "cidr"
    
    return False, "invalid"

class ProgressTracker:
    """Class for tracking scan progress"""
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.start_time = None
        self.last_update = None
        self.current_host = None
        self.current_port = None
        self.total_hosts = None
        self.scanned_hosts = 0
        self.is_network_scan = False
        self.lock = threading.Lock()

    def start(self):
        """Start progress tracking with validation"""
        self.start_time = datetime.now()
        self.last_update = self.start_time

        # Determine scan type
        is_valid, target_type = validate_target(self.target)
        
        if not is_valid:
            print(f"{Color.RED}[-]{Color.RESET} ERROR: Invalid target format '{self.target}'")
            print(f"{Color.RED}[-]{Color.RESET} Expected: IP address, CIDR (e.g., 192.168.1.0/24),")
            print(f"{Color.RED}[-]{Color.RESET}         IP range (e.g., 192.168.1.1-100),")
            print(f"{Color.RED}[-]{Color.RESET}         Multi-range (e.g., 192.168.0-100.0-100),")
            print(f"{Color.RED}[-]{Color.RESET}         or domain name")
            sys.exit(1)

        if target_type in ["cidr", "ip_range", "multi_range"]:
            self.is_network_scan = True
            
            if target_type == "cidr":
                parts = self.target.split('/')
                ip_part = parts[0]
                mask = int(parts[1])
                
                # Calculate number of hosts
                self.total_hosts = calculate_hosts_count(self.target, target_type)
                
                print(f"{Color.GREEN}[+]{Color.RESET} Valid CIDR target: {self.target}")
                print(f"{Color.CYAN}[i]{Color.RESET} Network: {ip_part}/{mask}")
                print(f"{Color.CYAN}[i]{Color.RESET} Usable hosts: {self.total_hosts}")
                
            elif target_type == "ip_range":
                print(f"{Color.GREEN}[+]{Color.RESET} Valid IP range target: {self.target}")
                
                # Calculate number of hosts
                self.total_hosts = calculate_hosts_count(self.target, target_type)
                if self.total_hosts:
                    print(f"{Color.CYAN}[i]{Color.RESET} Hosts to scan: {self.total_hosts}")
                else:
                    self.total_hosts = None
            
            elif target_type == "multi_range":
                print(f"{Color.GREEN}[+]{Color.RESET} Valid multi-range target: {self.target}")
                
                # Calculate number of hosts
                self.total_hosts = calculate_hosts_count(self.target, target_type)
                if self.total_hosts:
                    print(f"{Color.CYAN}[i]{Color.RESET} Hosts to scan: {self.total_hosts}")
                    
                    # Warn if too many hosts
                    if self.total_hosts > 1000:
                        print(f"{Color.YELLOW}[!]{Color.RESET} Warning: Large target range ({self.total_hosts} hosts)")
                        print(f"{Color.YELLOW}[!]{Color.RESET} Consider using CIDR notation or smaller ranges")
                else:
                    self.total_hosts = None
        
        elif target_type == "single_ip":
            print(f"{Color.GREEN}[+]{Color.RESET} Valid single IP target: {self.target}")
            self.total_hosts = 1
        
        elif target_type == "domain":
            print(f"{Color.GREEN}[+]{Color.RESET} Valid domain target: {self.target}")
            self.total_hosts = 1

        self.logger.info(f"Starting progress tracking for target: {self.target} (type: {target_type})")

    def update(self, line):
        """Update progress based on Nmap output line"""
        if not line:
            return

        line_lower = line.lower()

        with self.lock:
            # Determine current host
            host_match = re.search(r'scanning\s+(\d+\.\d+\.\d+\.\d+)', line_lower)
            if host_match:
                self.current_host = host_match.group(1)
                self.scanned_hosts += 1

            # Determine current port
            port_match = re.search(r'(\d+)/\w+\s+port', line_lower)
            if port_match:
                self.current_port = port_match.group(1)

            # Detect host scan completion
            if 'nmap scan report' in line_lower:
                self.scanned_hosts += 1

    def get_progress(self):
        """Get current progress percentage"""
        if not self.total_hosts or self.total_hosts <= 0:
            return None

        if self.scanned_hosts > self.total_hosts:
            return 100

        progress = (self.scanned_hosts / self.total_hosts) * 100
        return min(100, progress)

    def get_elapsed_time(self):
        """Get elapsed time"""
        if not self.start_time:
            return "00:00:00"

        elapsed = datetime.now() - self.start_time
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_status_string(self):
        """Get status string"""
        status = []

        if self.current_host:
            status.append(f"Host: {self.current_host}")

        if self.current_port:
            status.append(f"Port: {self.current_port}")

        if self.scanned_hosts > 0 and self.total_hosts:
            progress = self.get_progress()
            if progress is not None:
                status.append(f"Progress: {progress:.1f}% ({self.scanned_hosts}/{self.total_hosts} hosts)")

        elapsed = self.get_elapsed_time()
        status.append(f"Time: {elapsed}")

        return " | ".join(status)

class NmapScanner:
    def __init__(self, output_dir, nmap_args=None):
        self.output_dir = Path(output_dir)
        self.log_file = self.output_dir / "log.txt"  # Single log file
        self.reports_dir = self.output_dir / "reports"
        self.nmap_args = nmap_args if nmap_args else "-sV --top-ports 100"

        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

        # Setup logging
        self.setup_logging()

        # Dictionary for service-port mapping
        self.service_ports = {
            'web': [80, 443, 8080, 8443, 8000, 3000, 9000],
            'ftp': [20, 21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25, 465, 587],
            'dns': [53],
            'dhcp': [67, 68],
            'tftp': [69],
            'http-proxy': [3128, 8080, 8888],
            'snmp': [161],
            'ldap': [389, 636],
            'smb': [137, 138, 139, 445],
            'mysql': [3306],
            'postgresql': [5432],
            'mongodb': [27017],
            'rdp': [3389],
            'vnc': [5900, 5901],
            'redis': [6379],
            'elasticsearch': [9200, 9300],
            'docker': [2375, 2376],
            'kubernetes': [6443, 10250],
            'jenkins': [8080],
            'snmp': [161, 162, 6000, 6012],
        }

        self.known_services = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            53: 'DNS',
            3389: 'RDP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            9200: 'Elasticsearch',
            161: 'SNMP',
            161: 'SNMPTRAP',
            6000: 'SNMP',
            6012: 'SNMPTRAP',
        }

    def setup_logging(self):
        """Setup logging system"""
        # Create logger for console and file output
        self.logger = logging.getLogger('NmapScanner')
        self.logger.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # File handler (single log.txt file)
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

        # Clear existing handlers
        self.logger.handlers.clear()

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        self.logger.info(f"Scanner initialized. Directory: {self.output_dir}")
        self.logger.info(f"Nmap arguments: {self.nmap_args}")

    def estimate_scan_time(self, target, nmap_args, target_type):
        """Estimate scan time"""
        self.logger.info("Estimating scan time...")

        estimated_time = "unknown"

        # Determine number of ports
        if "-p-" in nmap_args or "--all-ports" in nmap_args:
            ports = 65535
            port_info = "all ports (65535)"
        elif "--top-ports" in nmap_args:
            match = re.search(r'--top-ports\s+(\d+)', nmap_args)
            if match:
                ports = int(match.group(1))
                port_info = f"top {ports} ports"
            else:
                ports = 100
                port_info = "top 100 ports"
        elif "-p" in nmap_args:
            # Try to parse port range
            match = re.search(r'-p\s+([\d,\-\s]+)', nmap_args)
            if match:
                port_range = match.group(1)
                # Simple estimation - count max port
                ports = 1000  # Conservative estimate
                port_info = f"specified ports ({port_range})"
            else:
                ports = 1000
                port_info = "specified ports"
        else:
            ports = 1000
            port_info = "standard ports"

        # Determine number of hosts
        hosts = calculate_hosts_count(target, target_type)
        if not hosts:
            hosts = 1
        
        if target_type == "cidr":
            host_info = f"{hosts} hosts in network {target}"
        elif target_type == "ip_range":
            host_info = f"{hosts} hosts in range {target}"
        elif target_type == "multi_range":
            host_info = f"{hosts} hosts in multi-range {target}"
        elif target_type == "domain":
            host_info = f"domain {target}"
        else:  # single_ip
            host_info = f"single host {target}"

        # Time estimation (very approximate)
        # Base time per port: 0.1-1 second depending on scan type
        base_time_per_port = 0.5

        if "-sS" in nmap_args:
            base_time_per_port = 0.1  # SYN scan is faster
        elif "-sT" in nmap_args:
            base_time_per_port = 0.3  # TCP connect is slower
        elif "-sU" in nmap_args:
            base_time_per_port = 2.0  # UDP scan is much slower

        if "-T0" in nmap_args or "-T1" in nmap_args:
            base_time_per_port *= 5
        elif "-T2" in nmap_args:
            base_time_per_port *= 2
        elif "-T3" in nmap_args:
            base_time_per_port *= 1
        elif "-T4" in nmap_args or "-T5" in nmap_args:
            base_time_per_port *= 0.5

        total_seconds = hosts * ports * base_time_per_port

        if total_seconds < 60:
            estimated_time = f"~{int(total_seconds)} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds / 60
            estimated_time = f"~{minutes:.1f} minutes"
        elif total_seconds < 86400:
            hours = total_seconds / 3600
            estimated_time = f"~{hours:.1f} hours"
        else:
            days = total_seconds / 86400
            estimated_time = f"~{days:.1f} days"

        self.logger.info(f"Estimation: {host_info}, {port_info}")
        self.logger.info(f"Estimated scan time: {estimated_time}")

        print(f"\nScan Estimation:")
        print(f"   Target: {host_info}")
        print(f"   Ports: {port_info}")
        print(f"   Estimated time: {estimated_time}")

        if total_seconds > 300:  # More than 5 minutes
            print(f"   {Color.YELLOW}[!]{Color.RESET} This may take some time...")
            print(f"   {Color.YELLOW}[!]{Color.RESET} Tip: Press Ctrl+C to interrupt")

        # Warn for very large scans
        if hosts > 10000:
            print(f"   {Color.YELLOW}[!]{Color.RESET} Warning: Very large range ({hosts} hosts)")
            print(f"   {Color.YELLOW}[!]{Color.RESET} Consider breaking into smaller scans")
            print(f"   {Color.YELLOW}[!]{Color.RESET} Or use fewer ports (e.g., --top-ports 10)")

        print()

    def run_nmap_scan(self, target, target_type):
        """Execute Nmap scan with progress display"""
        self.logger.info(f"Starting scan of target: {target}")

        # Validate target before scanning
        is_valid, detected_type = validate_target(target)
        if not is_valid:
            print(f"{Color.RED}[-]{Color.RESET} ERROR: Invalid target format '{target}'")
            print(f"{Color.RED}[-]{Color.RESET} Supported formats:")
            print(f"{Color.RED}[-]{Color.RESET}   - Single IP: 192.168.1.1")
            print(f"{Color.RED}[-]{Color.RESET}   - CIDR: 192.168.1.0/24")
            print(f"{Color.RED}[-]{Color.RESET}   - IP range: 192.168.1.1-100")
            print(f"{Color.RED}[-]{Color.RESET}   - Multi-range: 192.168.0-100.0-100")
            print(f"{Color.RED}[-]{Color.RESET}   - Domain: example.com")
            return None

        print(f"{Color.GREEN}[+]{Color.RESET} Target validated: {target} ({target_type})")

        # For multi-range targets, Nmap supports them natively
        # but we need to handle them specially
        if target_type == "multi_range":
            print(f"{Color.CYAN}[i]{Color.RESET} Multi-range format detected")
            print(f"{Color.CYAN}[i]{Color.RESET} Nmap will handle this format directly")

        # Estimate scan time
        self.estimate_scan_time(target, self.nmap_args, target_type)

        # Result file names
        xml_output = self.reports_dir / "scan_results.xml"
        normal_output = self.reports_dir / "scan_results.txt"

        # Command to execute
        cmd = f"nmap {self.nmap_args} -oX {xml_output} -oN {normal_output} {target}"

        self.logger.info(f"Executing command: {cmd}")
        print(f"\nStarting scan...")
        print(f"Command: {cmd}")

        # Initialize progress tracker
        progress_tracker = ProgressTracker(target, self.logger)
        progress_tracker.start()

        # Queue for output
        output_queue = queue.Queue()

        def read_output(pipe, queue):
            """Read output from pipe in separate thread"""
            try:
                for line in iter(pipe.readline, ''):
                    if line:
                        queue.put(line)
                pipe.close()
            except:
                pass

        try:
            # Start process
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Start threads for reading output
            stdout_thread = threading.Thread(
                target=read_output,
                args=(process.stdout, output_queue)
            )
            stderr_thread = threading.Thread(
                target=read_output,
                args=(process.stderr, output_queue)
            )

            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            # Collect output and display progress
            last_progress_update = time.time()
            lines_buffer = []

            while True:
                # Check if process completed
                if process.poll() is not None:
                    # Read remaining output
                    while not output_queue.empty():
                        line = output_queue.get_nowait()
                        if line:
                            lines_buffer.append(line)
                            progress_tracker.update(line)
                    break

                # Read output
                try:
                    line = output_queue.get(timeout=0.1)
                    if line:
                        lines_buffer.append(line)
                        progress_tracker.update(line)

                        # Show informative lines
                        pass

                except queue.Empty:
                    pass

                # Update progress display every 0.5 seconds
                current_time = time.time()
                if current_time - last_progress_update > 0.5:
                    status = progress_tracker.get_status_string()
                    if status:
                        print(f"\r{Color.BLUE}[*]{Color.RESET} {status}", end='', flush=True)
                    last_progress_update = current_time

            # Wait for threads to complete
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            # Get return code
            return_code = process.wait()

            if return_code == 0:
                print(f"\n{Color.GREEN}[+]{Color.RESET} Scan completed successfully!")
                self.logger.info("Scan completed successfully")

                # Save output to log
                full_output = ''.join(lines_buffer)
                if full_output:
                    self.logger.info("Nmap scan output saved to log file")

                return xml_output
            else:
                print(f"\n{Color.RED}[-]{Color.RESET} Nmap exited with error (code: {return_code})")
                self.logger.error(f"Nmap exited with error code: {return_code}")

                # Show errors
                error_lines = [line for line in lines_buffer if 'error' in line.lower()]
                for error_line in error_lines[:5]:  # First 5 errors
                    print(f"   {Color.RED}[-]{Color.RESET} {error_line.strip()}")

                return None

        except KeyboardInterrupt:
            print(f"\n\n{Color.YELLOW}[!]{Color.RESET} Interrupt signal received (Ctrl+C)")
            self.logger.warning("Scan interrupted by user")

            if 'process' in locals():
                print(f"   {Color.YELLOW}[!]{Color.RESET} Stopping scan...")
                process.terminate()

                try:
                    process.wait(timeout=5)
                    print(f"   {Color.GREEN}[+]{Color.RESET} Scan stopped")
                except subprocess.TimeoutExpired:
                    process.kill()
                    print(f"   {Color.YELLOW}[!]{Color.RESET} Process force terminated")

            # Check if files were created
            if xml_output.exists():
                file_size = xml_output.stat().st_size
                if file_size > 100:
                    print(f"   {Color.GREEN}[+]{Color.RESET} Partial results saved ({file_size} bytes)")
                    self.logger.info(f"Partial results saved ({file_size} bytes)")
                    return xml_output

            print(f"   {Color.RED}[-]{Color.RESET} Results not found or files are empty")
            return None

        except Exception as e:
            print(f"\n{Color.RED}[-]{Color.RESET} Unexpected error: {e}")
            self.logger.error(f"Unexpected error during scan: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output"""
        self.logger.info(f"Parsing XML file: {xml_file}")
        print(f"\nAnalyzing results...")

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            hosts_data = []
            total_hosts = len(root.findall('host'))
            processed = 0

            for host in root.findall('host'):
                host_info = self.parse_host(host)
                if host_info:
                    hosts_data.append(host_info)

                processed += 1
                progress = (processed / total_hosts) * 100 if total_hosts > 0 else 0
                print(f"\r   {Color.BLUE}[*]{Color.RESET} Processed hosts: {processed}/{total_hosts} ({progress:.1f}%)", end='', flush=True)

            print(f"\n{Color.GREEN}[+]{Color.RESET} Found hosts: {len(hosts_data)}")
            self.logger.info(f"Found hosts: {len(hosts_data)}")
            return hosts_data

        except ET.ParseError as e:
            self.logger.error(f"XML parsing error: {e}")
            print(f"{Color.RED}[-]{Color.RESET} Error parsing XML file")
            return []
        except Exception as e:
            self.logger.error(f"Error processing XML: {e}")
            print(f"{Color.RED}[-]{Color.RESET} Error processing results")
            return []

    def parse_host(self, host_element):
        """Parse information about a single host"""
        try:
            # Get address
            address_elem = host_element.find(".//address[@addrtype='ipv4']")
            if address_elem is None:
                return None

            ip_address = address_elem.get('addr')

            # Get hostname
            hostname_elem = host_element.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else "Unknown"

            # Get ports
            ports_data = []
            ports_element = host_element.find('ports')

            if ports_element is not None:
                total_ports = len(ports_element.findall('port'))
                processed_ports = 0

                for port_element in ports_element.findall('port'):
                    port_info = self.parse_port(port_element)
                    if port_info:
                        ports_data.append(port_info)

                    processed_ports += 1

            return {
                'ip': ip_address,
                'hostname': hostname,
                'ports': ports_data
            }

        except Exception as e:
            self.logger.error(f"Error parsing host: {e}")
            return None

    def parse_port(self, port_element):
        """Parse information about a port"""
        try:
            port_id = port_element.get('portid')
            protocol = port_element.get('protocol')

            state_elem = port_element.find('state')
            state = state_elem.get('state') if state_elem is not None else "unknown"

            if state != 'open':
                return None

            service_elem = port_element.find('service')
            service_name = service_elem.get('name') if service_elem is not None else "unknown"
            service_product = service_elem.get('product', '')
            service_version = service_elem.get('version', '')

            # Script information
            scripts_info = []
            script_elem = port_element.find('script')
            if script_elem is not None:
                scripts_info.append({
                    'id': script_elem.get('id'),
                    'output': script_elem.get('output', '')
                })

            return {
                'port': int(port_id),
                'protocol': protocol,
                'service': service_name,
                'product': service_product,
                'version': service_version,
                'scripts': scripts_info
            }

        except Exception as e:
            self.logger.error(f"Error parsing port: {e}")
            return None

    def create_service_files(self, hosts_data):
        """Create files by service types"""
        self.logger.info("Creating service-based result files")
        print(f"\nCreating reports...")

        # Group by services
        service_groups = defaultdict(list)

        total_ports = sum(len(host['ports']) for host in hosts_data)
        processed_ports = 0

        for host in hosts_data:
            for port_info in host['ports']:
                port = port_info['port']
                service = port_info['service']

                # Determine service category
                category = self.get_service_category(port, service)

                service_groups[category].append({
                    'host': host['ip'],
                    'hostname': host['hostname'],
                    'port': port,
                    'service': service,
                    'product': port_info['product'],
                    'version': port_info['version']
                })

                processed_ports += 1
                progress = (processed_ports / total_ports) * 100 if total_ports > 0 else 0
                print(f"\r   {Color.BLUE}[*]{Color.RESET} Classifying ports: {processed_ports}/{total_ports} ({progress:.1f}%)", end='', flush=True)

        print()

        # Create files for each category
        categories = list(service_groups.keys())
        total_categories = len(categories)

        for i, category in enumerate(categories):
            hosts = service_groups[category]
            if hosts:
                filename = f"{category}_ports.txt"
                filepath = self.reports_dir / filename

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"# {category.upper()} PORTS\n")
                    f.write(f"# Total found: {len(hosts)}\n")
                    f.write("#" * 50 + "\n\n")

                    for item in hosts:
                        f.write(f"IP: {item['host']}\n")
                        f.write(f"Hostname: {item['hostname']}\n")
                        f.write(f"Port: {item['port']}\n")
                        f.write(f"Service: {item['service']}\n")
                        if item['product']:
                            f.write(f"Product: {item['product']}\n")
                        if item['version']:
                            f.write(f"Version: {item['version']}\n")
                        f.write("-" * 30 + "\n")

                print(f"   {Color.GREEN}[+]{Color.RESET} Created {filename} ({len(hosts)} entries)")
                self.logger.info(f"Created file: {filename} ({len(hosts)} entries)")

        # Create general file with all open ports
        self.create_summary_file(hosts_data)

    def get_service_category(self, port, service_name):
        """Determine service category by port and name"""
        port = int(port)

        # Check by known ports
        for category, ports in self.service_ports.items():
            if port in ports:
                return category

        # Check by service name
        service_name_lower = service_name.lower()

        if any(web in service_name_lower for web in ['http', 'apache', 'nginx', 'iis']):
            return 'web'
        elif 'ssh' in service_name_lower:
            return 'ssh'
        elif 'ftp' in service_name_lower:
            return 'ftp'
        elif 'smtp' in service_name_lower:
            return 'smtp'
        elif 'dns' in service_name_lower:
            return 'dns'
        elif 'mysql' in service_name_lower or 'mariadb' in service_name_lower:
            return 'mysql'
        elif 'postgres' in service_name_lower:
            return 'postgresql'
        elif 'rdp' in service_name_lower or 'remote-desktop' in service_name_lower:
            return 'rdp'
        elif 'vnc' in service_name_lower:
            return 'vnc'
        elif 'smb' in service_name_lower or 'samba' in service_name_lower:
            return 'smb'
        elif 'snmp' in service_name_lower or 'snmptrap' in service_name_lower:
            return 'snmp'

        # If category not determined
        return 'other'

    def create_summary_file(self, hosts_data):
        """Create general file with results"""
        summary_file = self.reports_dir / "all_open_ports.txt"

        print(f"   {Color.BLUE}[*]{Color.RESET} Creating general report...")

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# GENERAL SCAN REPORT\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" * 60 + "\n\n")

            total_hosts = len(hosts_data)
            total_ports = sum(len(host['ports']) for host in hosts_data)

            f.write(f"Total hosts: {total_hosts}\n")
            f.write(f"Total open ports: {total_ports}\n\n")

            for i, host in enumerate(hosts_data):
                f.write(f"Host: {host['ip']} ({host['hostname']})\n")

                if host['ports']:
                    for port_info in host['ports']:
                        port_str = f"  {port_info['port']}/{port_info['protocol']}"
                        service_str = f"{port_info['service']}"

                        if port_info['product']:
                            service_str += f" ({port_info['product']}"
                            if port_info['version']:
                                service_str += f" {port_info['version']}"
                            service_str += ")"

                        f.write(f"{port_str:10} {service_str}\n")
                else:
                    f.write("  No open ports\n")

                f.write("\n")

                # Writing progress
                progress = ((i + 1) / total_hosts) * 100 if total_hosts > 0 else 0
                print(f"\r   {Color.BLUE}[*]{Color.RESET} Writing report: {i+1}/{total_hosts} hosts ({progress:.1f}%)", end='', flush=True)

        print(f"\n{Color.GREEN}[+]{Color.RESET} General report created")
        self.logger.info(f"Created general report file: {summary_file}")

    def generate_html_report(self, xml_file):
        """Generate HTML report from XML"""
        self.logger.info("Generating HTML report")
        print(f"\nCreating HTML report...")

        html_output = self.reports_dir / "scan_report.html"
        xslt_file = "/usr/share/nmap/nmap.xsl"  # Standard XSLT path in Linux

        # Check if XSLT file exists
        if not os.path.exists(xslt_file):
            self.logger.warning(f"XSLT file not found: {xslt_file}")
            self.logger.info("Trying to find alternative XSLT file...")

            # Search alternative paths
            alternative_paths = [
                "/usr/local/share/nmap/nmap.xsl",
                "/opt/homebrew/share/nmap/nmap.xsl",  # For macOS with Homebrew
                "nmap.xsl"  # In current directory
            ]

            for path in alternative_paths:
                if os.path.exists(path):
                    xslt_file = path
                    self.logger.info(f"Found XSLT file: {xslt_file}")
                    print(f"   {Color.CYAN}[i]{Color.RESET} Found XSLT file: {xslt_file}")
                    break
            else:
                self.logger.error("XSLT file not found. HTML report will not be created.")
                self.logger.info("Install nmap or specify nmap.xsl path manually")
                print(f"   {Color.YELLOW}[!]{Color.RESET} XSLT file not found. Creating simple report...")
                self.create_simple_html_report(xml_file)
                return True

        try:
            # Use xsltproc to convert XML to HTML
            cmd = f"xsltproc -o {html_output} {xslt_file} {xml_file}"

            print(f"   {Color.BLUE}[*]{Color.RESET} Converting XML to HTML...")
            self.logger.info(f"Executing conversion: {cmd}")

            # Show conversion progress
            start_time = time.time()
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )

            elapsed = time.time() - start_time
            print(f"   {Color.GREEN}[+]{Color.RESET} HTML report created in {elapsed:.1f} seconds")
            self.logger.info("HTML report successfully created")
            return True

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error creating HTML report: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            print(f"   {Color.YELLOW}[!]{Color.RESET} Error creating HTML report. Creating simple version...")

            # Try to create simple HTML report manually
            self.create_simple_html_report(xml_file)
            return True

        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            print(f"   {Color.RED}[-]{Color.RESET} Error creating report: {e}")
            return False

    def create_simple_html_report(self, xml_file):
        """Create simple HTML report manually"""
        self.logger.info("Creating simple HTML report")
        print(f"   {Color.BLUE}[*]{Color.RESET} Creating simple HTML report...")

        html_output = self.reports_dir / "scan_report_simple.html"
        hosts_data = self.parse_nmap_xml(xml_file)

        if not hosts_data:
            print(f"   {Color.RED}[-]{Color.RESET} No data for report")
            return

        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 30px; }
        .host { background: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
        .host-header { background: #4CAF50; color: white; padding: 10px; border-radius: 3px; margin: -15px -15px 15px -15px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .timestamp { color: #666; font-style: italic; }
        .service-web { background-color: #e3f2fd; }
        .service-ssh { background-color: #f3e5f5; }
        .service-ftp { background-color: #e8f5e8; }
        .category { padding: 3px 8px; border-radius: 3px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Nmap Scan Report</h1>
        <div class="timestamp">Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</div>

        <div class="summary">
            <h2>Statistics</h2>"""

        # Add statistics
        total_hosts = len(hosts_data)
        total_ports = sum(len(host['ports']) for host in hosts_data)

        # Count by categories
        categories = {}
        for host in hosts_data:
            for port_info in host['ports']:
                category = self.get_service_category(port_info['port'], port_info['service'])
                categories[category] = categories.get(category, 0) + 1

        html_content += f"""
            <p><strong>Total hosts:</strong> {total_hosts}</p>
            <p><strong>Total open ports:</strong> {total_ports}</p>"""

        # Add category statistics
        if categories:
            html_content += "<p><strong>Service distribution:</strong></p><ul>"
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_ports * 100) if total_ports > 0 else 0
                html_content += f"<li>{category}: {count} ports ({percentage:.1f}%)</li>"
            html_content += "</ul>"

        html_content += """
        </div>

        <h2>Results by Host</h2>"""

        # Add information for each host
        for host in hosts_data:
            html_content += f"""
        <div class="host">
            <div class="host-header">
                <h3>{host['ip']} ({host['hostname']})</h3>
            </div>"""

            if host['ports']:
                html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>"""

                for port_info in host['ports']:
                    category = self.get_service_category(port_info['port'], port_info['service'])
                    service_class = f"service-{category}"
                    html_content += f"""
                    <tr class="{service_class}">
                        <td><strong>{port_info['port']}</strong></td>
                        <td>{port_info['protocol']}</td>
                        <td>{port_info['service']}</td>
                        <td>{port_info['product']}</td>
                        <td>{port_info['version']}</td>
                        <td><span class="category">{category}</span></td>
                    </tr>"""

                html_content += """
                </tbody>
            </table>"""
            else:
                html_content += "<p>No open ports</p>"

            html_content += "</div>"

        html_content += """
    </div>
</body>
</html>"""

        with open(html_output, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"   {Color.GREEN}[+]{Color.RESET} Simple HTML report created")
        self.logger.info(f"Created simple HTML report: {html_output}")

    def run(self, target, target_type):
        """Main method to start scan and analysis"""
        self.logger.info(f"Starting scan of target: {target}")

        print(f"\n{'='*60}")
        print("STARTING NMAP SCAN")
        print('='*60)
        print(f"Target: {target}")
        print(f"Parameters: {self.nmap_args}")
        print(f"Directory: {self.output_dir}")
        print('='*60)

        # Execute scan
        xml_file = self.run_nmap_scan(target, target_type)

        if not xml_file or not xml_file.exists():
            self.logger.error("Scan failed or XML file not created")
            print(f"\n{Color.RED}[-]{Color.RESET} Scan failed")
            return False

        print(f"\n{'='*60}")
        print("ANALYZING RESULTS")
        print('='*60)

        # Parse results
        hosts_data = self.parse_nmap_xml(xml_file)

        if not hosts_data:
            self.logger.warning("No data for analysis")
            print(f"\n{Color.YELLOW}[!]{Color.RESET} No open ports for analysis")
            return False

        # Create service-based files
        self.create_service_files(hosts_data)

        # Generate HTML report
        self.generate_html_report(xml_file)

        print(f"\n{'='*60}")
        print(f"{Color.GREEN}[+]{Color.RESET} ANALYSIS COMPLETED SUCCESSFULLY!")
        print('='*60)
        self.logger.info("Analysis completed successfully!")
        self.print_summary()

        return True

    def print_summary(self):
        """Print results summary"""
        print(f"\nRESULTS SUMMARY")
        print('='*60)
        print(f"Results directory: {self.output_dir}")
        print(f"Log file: {self.log_file}")
        print(f"Reports: {self.reports_dir}")
        print(f"\nCreated files:")

        files = list(self.reports_dir.iterdir())
        if files:
            for i, file in enumerate(files, 1):
                if file.is_file():
                    size_kb = file.stat().st_size / 1024
                    print(f"   {i:2d}. {file.name:30} ({size_kb:.1f} KB)")
        else:
            print(f"   {Color.RED}[-]{Color.RESET} No files found")

        print(f"\nTip: Open {self.reports_dir}/scan_report.html in browser")
        print(f"     to view results in convenient format")
        print('='*60)

def main():
    parser = argparse.ArgumentParser(
        description='Nmap Scan Analyzer - automates Nmap scanning and results analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  %(prog)s 192.168.1.1 -D scan_results
  %(prog)s 192.168.0.0/24 -D network_scan -n "-sS -sV -p 1-1000"
  %(prog)s scanme.nmap.org -D internet_scan -n "-sC -sV --top-ports 1000"
  %(prog)s 192.168.1.1-100 -D range_scan -n "-sS -sV"
  %(prog)s 192.168.0-100.0-100 -D multi_range_scan -n "-sS -sV --top-ports 50"

IMPORTANT: Use -p- (all ports) only for single hosts.
For networks use --top-ports N or specific port ranges.
        """
    )

    parser.add_argument('target', help='Scan target (IP, CIDR, IP range, multi-range or domain)')
    parser.add_argument('-D', '--directory', required=True,
                       help='Directory name to save results')
    parser.add_argument('-n', '--nmap-args',
                       default='-sV --top-ports 100',
                       help='Arguments for Nmap (default: -sV --top-ports 100)')

    args = parser.parse_args()

    # Validate target before creating scanner
    is_valid, target_type = validate_target(args.target)
    if not is_valid:
        print(f"{Color.RED}[-]{Color.RESET} ERROR: Invalid target format '{args.target}'")
        print(f"{Color.RED}[-]{Color.RESET} Supported formats:")
        print(f"{Color.RED}[-]{Color.RESET}   - Single IP: 192.168.1.1")
        print(f"{Color.RED}[-]{Color.RESET}   - CIDR: 192.168.1.0/24")
        print(f"{Color.RED}[-]{Color.RESET}   - IP range: 192.168.1.1-100")
        print(f"{Color.RED}[-]{Color.RESET}   - Multi-range: 192.168.0-100.0-100")
        print(f"{Color.RED}[-]{Color.RESET}   - Domain: example.com")
        sys.exit(1)

    print(f"{Color.GREEN}[+]{Color.RESET} Target validated: {args.target} ({target_type})")

    # Calculate number of hosts for large scans warning
    hosts_count = calculate_hosts_count(args.target, target_type)
    
    # Warn for large scans and ask for confirmation
    if hosts_count and hosts_count > 10000:
        print(f"\n{Color.YELLOW}[!]{Color.RESET} WARNING: LARGE SCAN DETECTED")
        print(f"{Color.YELLOW}[!]{Color.RESET} Target: {args.target}")
        print(f"{Color.YELLOW}[!]{Color.RESET} Estimated hosts: {hosts_count}")
        print(f"{Color.YELLOW}[!]{Color.RESET} This scan may take a VERY long time")
        print(f"{Color.YELLOW}[!]{Color.RESET} Consider using smaller ranges or fewer ports")
        
        # Ask for confirmation
        response = input(f"\n{Color.YELLOW}[?]{Color.RESET} Continue with scan? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print(f"\n{Color.YELLOW}[!]{Color.RESET} Scan cancelled by user")
            sys.exit(0)
        
        # Double check for extremely large scans
        if hosts_count > 50000:
            print(f"\n{Color.RED}[!]{Color.RESET} EXTREME WARNING: {hosts_count} HOSTS")
            print(f"{Color.RED}[!]{Color.RESET} This scan could take days or weeks!")
            response2 = input(f"\n{Color.RED}[?]{Color.RESET} Are you REALLY sure? (yes/NO): ").strip().lower()
            if response2 != 'yes':
                print(f"\n{Color.YELLOW}[!]{Color.RESET} Scan cancelled")
                sys.exit(0)

    # Create scanner instance
    scanner = NmapScanner(args.directory, args.nmap_args)

    # Start scan
    success = scanner.run(args.target, target_type)

    if success:
        print(f"\n{Color.GREEN}[+]{Color.RESET} ALL OPERATIONS COMPLETED SUCCESSFULLY!")
        print(f"Results saved to: {args.directory}")
        print(f"Log file: {args.directory}/log.txt")
        sys.exit(0)
    else:
        print(f"\n{Color.RED}[-]{Color.RESET} SCAN COMPLETED WITH ERRORS OR INTERRUPTED")
        print(f"Check log file: {args.directory}/log.txt")
        sys.exit(1)

if __name__ == "__main__":
    # Check if nmap is installed
    if shutil.which("nmap") is None:
        print(f"{Color.RED}[-]{Color.RESET} Error: Nmap not installed or not found in PATH")
        print("Install Nmap to use this script")
        print("Ubuntu/Debian: sudo apt-get install nmap")
        print("CentOS/RHEL: sudo yum install nmap")
        print("macOS: brew install nmap")
        sys.exit(1)

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}[!]{Color.RESET} Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}[-]{Color.RESET} Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)