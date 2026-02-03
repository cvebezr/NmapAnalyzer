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
import concurrent.futures
import json

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

def print_banner():
    """Print NmapAnalyzer banner"""
    banner = f"""
╔══════════════════════════════════════════╗ 
║                                          ║   
║  ███╗   ██╗███╗   ███╗ █████╗ ██████╗    ║  
║  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗   ║ 
║  ██╔██╗ ██║██╔████╔██║███████║██████╔╝   ║
║  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝    ║
║  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║        ║
║   ╔═╗ ╦  ╦ ╔═╗ ╦  ╦ ╦ ╔═╗ ╔═╗ ╦═╗        ║
║   ╠═╣ ║╲╲║ ╠═╣ ║  \\ /  /  ║╣  ╠╦╝        ║
║   ╩ ╩ ╩  ╩ ╩ ╩ ╩═╝ ╩  ╚═╝ ╚═╝ ╩╚═        ║
╚══════════════════════════════════════════╝
BY CVEBEZR
"""
    print(banner)

class ScanProfiles:
    """Predefined scan profiles"""
    PROFILES = {
        'quick': {
            'args': '-sS -T4 --top-ports 20',
            'description': 'Quick SYN scan of top 20 ports',
            'time': 'Fast',
            'stealth': 'High'
        },
        'standart': {
            'args': '-sS -sV -T4 --top-ports 100',
            'description': 'Standart SYN scan with version detection',
            'time': 'Medium',
            'stealth': 'Medium'
        },
        'full': {
            'args': '-sS -sV -sC -T4 -A',
            'description': 'Full scan with scripts and OS detection',
            'time': 'Slow',
            'stealth': 'Low'
        },
        'udp': {
            'args': '-sU -T4 --top-ports 20',
            'description': 'UDP scan of top 20 ports',
            'time': 'Very Slow',
            'stealth': 'Medium'
        },
        'stealth': {
            'args': '-sS -T2 -f --top-ports 50',
            'description': 'Stealth scan with fragmentation',
            'time': 'Slow',
            'stealth': 'Very High'
        },
        'comprehensive': {
            'args': '-sS -sV -sC -A -p-',
            'description': 'Comprehensive all-port scan',
            'time': 'Very Slow',
            'stealth': 'Very Low'
        }
    }

    @classmethod
    def get_profile(cls, profile_name):
        """Get profile by name"""
        return cls.PROFILES.get(profile_name, cls.PROFILES['standart'])

    @classmethod
    def list_profiles(cls):
        """List all available profiles"""
        return list(cls.PROFILES.keys())

    @classmethod
    def get_profile_info(cls, profile_name):
        """Get detailed profile information"""
        profile = cls.get_profile(profile_name)
        return f"""
Profile: {profile_name}
Arguments: {profile['args']}
Description: {profile['description']}
Estimated Time: {profile['time']}
Stealth Level: {profile['stealth']}
        """

def validate_ip_address(ip_str):
    """Validate IPv4 address format"""
    pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = pattern.match(ip_str)
    if not match:
        return False
    
    for octet in match.groups():
        if not (0 <= int(octet) <= 255):
            return False
    
    return True

def validate_ip_range(ip_range):
    """Validate IP range format"""
    if '-' not in ip_range:
        return False
    
    if ip_range.count('.') == 3 and ip_range.count('-') == 1:
        parts = ip_range.split('-')
        if len(parts) != 2:
            return False
        
        ip_part = parts[0]
        range_part = parts[1]
        
        if not validate_ip_address(ip_part):
            return False
        
        try:
            range_num = int(range_part)
            if not (1 <= range_num <= 254):
                return False
        except ValueError:
            return False
        
        return True
    
    return validate_multi_range(ip_range)

def validate_multi_range(multi_range):
    """Validate multi-range format"""
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
    """Expand multi-range to individual IPs"""
    parts = multi_range.split('.')
    expanded_ranges = []
    
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            expanded_ranges.append(list(range(start, end + 1)))
        else:
            expanded_ranges.append([int(part)])
    
    from itertools import product
    ips = []
    for combination in product(*expanded_ranges):
        ip = '.'.join(map(str, combination))
        ips.append(ip)
    
    return ips

def calculate_hosts_count(target, target_type):
    """Calculate number of hosts"""
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
    
    if not validate_ip_address(ip_part):
        return False
    
    try:
        mask = int(mask_part)
        if not (0 <= mask <= 32):
            return False
    except ValueError:
        return False
    
    return True

def validate_target(target):
    """Validate scan target"""
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        return True, "domain"
    
    if validate_ip_address(target):
        return True, "single_ip"
    
    if validate_ip_range(target):
        if '-' in target and target.count('.') == 3 and target.count('-') == 1:
            parts = target.split('-')
            if '.' in parts[0] and not '.' in parts[1]:
                return True, "ip_range"
        return True, "multi_range"
    
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
        """Start progress tracking"""
        self.start_time = datetime.now()
        self.last_update = self.start_time

        is_valid, target_type = validate_target(self.target)
        
        if not is_valid:
            print(f"{Color.RED}[-]{Color.RESET} ERROR: Invalid target format '{self.target}'")
            sys.exit(1)

        if target_type in ["cidr", "ip_range", "multi_range"]:
            self.is_network_scan = True
            self.total_hosts = calculate_hosts_count(self.target, target_type)
        elif target_type in ["single_ip", "domain"]:
            self.total_hosts = 1

        self.logger.info(f"Starting progress tracking for target: {self.target}")

    def update(self, line):
        """Update progress based on Nmap output"""
        if not line:
            return

        line_lower = line.lower()

        with self.lock:
            host_match = re.search(r'scanning\s+(\d+\.\d+\.\d+\.\d+)', line_lower)
            if host_match:
                self.current_host = host_match.group(1)
                self.scanned_hosts += 1

            port_match = re.search(r'(\d+)/\w+\s+port', line_lower)
            if port_match:
                self.current_port = port_match.group(1)

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

    def get_elapsed_seconds(self):
        """Get elapsed time in seconds"""
        if not self.start_time:
            return 0
        return (datetime.now() - self.start_time).total_seconds()

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
                status.append(f"Progress: {progress:.1f}% ({self.scanned_hosts}/{self.total_hosts})")

        elapsed = self.get_elapsed_time()
        status.append(f"Time: {elapsed}")

        return " | ".join(status)

class ParallelScanner:
    """Parallel scanning manager"""
    
    def __init__(self, scanner_instance, max_workers=4):
        self.scanner = scanner_instance
        self.max_workers = max_workers
        self.results = []
        
    def split_target(self, target, target_type):
        """Split target into smaller chunks for parallel scanning"""
        chunks = []
        
        if target_type == "cidr":
            parts = target.split('/')
            base_ip = parts[0]
            mask = int(parts[1])
            
            if mask <= 24:
                new_mask = 24
                networks = 2 ** (24 - mask) if mask < 24 else 1
                for i in range(networks):
                    network_ip = f"{base_ip.rsplit('.', 1)[0]}.{i}"
                    chunks.append(f"{network_ip}.0/{new_mask}")
        
        elif target_type == "multi_range":
            ips = expand_multi_range(target)
            chunk_size = max(1, len(ips) // self.max_workers)
            
            for i in range(0, len(ips), chunk_size):
                chunk_ips = ips[i:i + chunk_size]
                if chunk_ips:
                    chunks.append(f"{chunk_ips[0]}-{chunk_ips[-1].split('.')[-1]}")
        
        elif target_type == "ip_range":
            parts = target.split('-')
            ip_base = parts[0]
            range_end = int(parts[1])
            ip_parts = ip_base.split('.')
            
            if len(ip_parts) == 4:
                start = int(ip_parts[3])
                total = range_end - start + 1
                chunk_size = max(1, total // self.max_workers)
                
                for i in range(start, range_end + 1, chunk_size):
                    end = min(i + chunk_size - 1, range_end)
                    chunks.append(f"{ip_base.rsplit('.', 1)[0]}.{i}-{end}")
        
        if not chunks:
            chunks = [target]
            
        return chunks
    
    def scan_chunk(self, chunk_target):
        """Scan a single chunk"""
        try:
            import tempfile
            import uuid
            temp_dir = Path(tempfile.gettempdir()) / f"nmap_chunk_{uuid.uuid4().hex[:8]}"
            temp_dir.mkdir(exist_ok=True)
            
            chunk_scanner = NmapScanner(str(temp_dir), self.scanner.nmap_args)
            
            xml_file = chunk_scanner.run_nmap_scan(chunk_target, "chunk")
            
            if xml_file and xml_file.exists():
                hosts_data = chunk_scanner.parse_nmap_xml(xml_file)
                
                shutil.rmtree(temp_dir, ignore_errors=True)
                
                return {
                    'target': chunk_target,
                    'hosts': hosts_data,
                    'success': True
                }
            else:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return {
                    'target': chunk_target,
                    'hosts': [],
                    'success': False,
                    'error': 'Scan failed'
                }
                
        except Exception as e:
            return {
                'target': chunk_target,
                'hosts': [],
                'success': False,
                'error': str(e)
            }
    
    def parallel_scan(self, target, target_type):
        """Execute parallel scan"""
        print(f"{Color.CYAN}[i]{Color.RESET} Setting up parallel scan ({self.max_workers} workers)...")
        
        chunks = self.split_target(target, target_type)
        
        if len(chunks) == 1:
            print(f"{Color.YELLOW}[!]{Color.RESET} Cannot parallelize this target. Running single scan.")
            return None
        
        print(f"{Color.CYAN}[i]{Color.RESET} Split into {len(chunks)} chunks")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_chunk = {
                executor.submit(self.scan_chunk, chunk): chunk 
                for chunk in chunks
            }
            
            results = []
            completed = 0
            total = len(chunks)
            
            for future in concurrent.futures.as_completed(future_to_chunk):
                chunk = future_to_chunk[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['success']:
                        print(f"{Color.GREEN}[+]{Color.RESET} Chunk '{chunk}' completed ({completed}/{total})")
                        print(f"   Found {len(result['hosts'])} hosts")
                    else:
                        print(f"{Color.RED}[-]{Color.RESET} Chunk '{chunk}' failed: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    print(f"{Color.RED}[-]{Color.RESET} Chunk '{chunk}' error: {e}")
                    results.append({
                        'target': chunk,
                        'hosts': [],
                        'success': False,
                        'error': str(e)
                    })
        
        all_hosts = []
        successful_chunks = 0
        
        for result in results:
            if result['success']:
                all_hosts.extend(result['hosts'])
                successful_chunks += 1
        
        print(f"\n{Color.CYAN}[i]{Color.RESET} Parallel scan completed")
        print(f"   Successful chunks: {successful_chunks}/{len(chunks)}")
        print(f"   Total hosts found: {len(all_hosts)}")
        
        return all_hosts

class NmapScanner:
    def __init__(self, output_dir, nmap_args=None):
        self.output_dir = Path(output_dir)
        self.log_file = self.output_dir / "log.txt"
        self.reports_dir = self.output_dir / "reports"
        self.nmap_args = nmap_args if nmap_args else "-sV --top-ports 100"
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_stats = {
            'total_hosts': 0,
            'open_ports': 0,
            'services_found': defaultdict(int),
            'scan_duration': 0
        }

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

        self.setup_logging()

        self.service_ports = {
            'web': [80, 443, 8080, 8443, 8000, 3000, 9000],
            'ftp': [20, 21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25, 465, 587],
            'dns': [53],
            'smb': [137, 138, 139, 445],
            'mysql': [3306],
            'postgresql': [5432],
            'mongodb': [27017],
            'rdp': [3389],
            'vnc': [5900, 5901],
            'redis': [6379],
            'elasticsearch': [9200, 9300],
        }

    def setup_logging(self):
        """Setup logging system"""
        self.logger = logging.getLogger('NmapScanner')
        self.logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

        self.logger.handlers.clear()
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        self.logger.info(f"Scanner initialized. Directory: {self.output_dir}")
        self.logger.info(f"Nmap arguments: {self.nmap_args}")

    def estimate_scan_time(self, target, nmap_args, target_type):
        """Estimate scan time"""
        self.logger.info("Estimating scan time...")

        estimated_time = "unknown"
        hosts = calculate_hosts_count(target, target_type) or 1

        if "-p-" in nmap_args or "--all-ports" in nmap_args:
            ports = 65535
            port_info = "all ports (65535)"
        elif "--top-ports" in nmap_args:
            match = re.search(r'--top-ports\s+(\d+)', nmap_args)
            ports = int(match.group(1)) if match else 100
            port_info = f"top {ports} ports"
        else:
            ports = 1000
            port_info = "standart ports"

        base_time_per_port = 0.5

        if "-sS" in nmap_args:
            base_time_per_port = 0.1
        elif "-sT" in nmap_args:
            base_time_per_port = 0.3
        elif "-sU" in nmap_args:
            base_time_per_port = 2.0

        if "-T0" in nmap_args or "-T1" in nmap_args:
            base_time_per_port *= 5
        elif "-T2" in nmap_args:
            base_time_per_port *= 2
        elif "-T4" in nmap_args or "-T5" in nmap_args:
            base_time_per_port *= 0.5

        total_seconds = hosts * ports * base_time_per_port

        if total_seconds < 60:
            estimated_time = f"~{int(total_seconds)} seconds"
        elif total_seconds < 3600:
            estimated_time = f"~{total_seconds/60:.1f} minutes"
        elif total_seconds < 86400:
            estimated_time = f"~{total_seconds/3600:.1f} hours"
        else:
            estimated_time = f"~{total_seconds/86400:.1f} days"

        print(f"\nScan Estimation:")
        print(f"   Hosts: {hosts}")
        print(f"   Ports: {port_info}")
        print(f"   Estimated time: {estimated_time}")

        if total_seconds > 300:
            print(f"   {Color.YELLOW}[!]{Color.RESET} This may take some time...")

        print()
        return total_seconds

    def run_nmap_scan(self, target, target_type):
        """Execute Nmap scan with progress display"""
        self.scan_start_time = datetime.now()
        self.logger.info(f"Starting scan of target: {target}")

        is_valid, detected_type = validate_target(target)
        if not is_valid:
            print(f"{Color.RED}[-]{Color.RESET} ERROR: Invalid target format")
            return None

        print(f"{Color.GREEN}[+]{Color.RESET} Target: {target} ({target_type})")

        self.estimate_scan_time(target, self.nmap_args, target_type)

        xml_output = self.reports_dir / "scan_results.xml"
        normal_output = self.reports_dir / "scan_results.txt"

        cmd = f"nmap {self.nmap_args} -oX {xml_output} -oN {normal_output} {target}"

        self.logger.info(f"Command: {cmd}")
        print(f"\nStarting scan...")

        progress_tracker = ProgressTracker(target, self.logger)
        progress_tracker.start()

        output_queue = queue.Queue()

        def read_output(pipe, queue):
            try:
                for line in iter(pipe.readline, ''):
                    if line:
                        queue.put(line)
                pipe.close()
            except:
                pass

        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

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

            last_progress_update = time.time()
            lines_buffer = []

            while True:
                if process.poll() is not None:
                    while not output_queue.empty():
                        line = output_queue.get_nowait()
                        if line:
                            lines_buffer.append(line)
                            progress_tracker.update(line)
                    break

                try:
                    line = output_queue.get(timeout=0.1)
                    if line:
                        lines_buffer.append(line)
                        progress_tracker.update(line)
                except queue.Empty:
                    pass

                current_time = time.time()
                if current_time - last_progress_update > 0.5:
                    status = progress_tracker.get_status_string()
                    if status:
                        print(f"\r{Color.BLUE}[*]{Color.RESET} {status}", end='', flush=True)
                    last_progress_update = current_time

            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            return_code = process.wait()

            self.scan_end_time = datetime.now()
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            self.scan_stats['scan_duration'] = scan_duration

            if return_code == 0:
                print(f"\n{Color.GREEN}[+]{Color.RESET} Scan completed in {scan_duration:.1f} seconds!")
                self.logger.info(f"Scan completed in {scan_duration:.1f} seconds")
                return xml_output
            else:
                print(f"\n{Color.RED}[-]{Color.RESET} Nmap error (code: {return_code})")
                return None

        except KeyboardInterrupt:
            print(f"\n\n{Color.YELLOW}[!]{Color.RESET} Scan interrupted")
            self.logger.warning("Scan interrupted by user")
            return None

        except Exception as e:
            print(f"\n{Color.RED}[-]{Color.RESET} Error: {e}")
            self.logger.error(f"Scan error: {e}")
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

            for host in root.findall('host'):
                host_info = self.parse_host(host)
                if host_info:
                    hosts_data.append(host_info)
                    
                    self.scan_stats['total_hosts'] += 1
                    self.scan_stats['open_ports'] += len(host_info['ports'])
                    
                    for port_info in host_info['ports']:
                        category = self.get_service_category(port_info['port'], port_info['service'])
                        self.scan_stats['services_found'][category] += 1

            print(f"{Color.GREEN}[+]{Color.RESET} Found {len(hosts_data)} hosts")
            self.logger.info(f"Found {len(hosts_data)} hosts")
            return hosts_data

        except Exception as e:
            self.logger.error(f"XML parsing error: {e}")
            print(f"{Color.RED}[-]{Color.RESET} Error parsing results")
            return []

    def parse_host(self, host_element):
        """Parse information about a single host"""
        try:
            address_elem = host_element.find(".//address[@addrtype='ipv4']")
            if address_elem is None:
                return None

            ip_address = address_elem.get('addr')
            hostname_elem = host_element.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else "Unknown"

            ports_data = []
            ports_element = host_element.find('ports')

            if ports_element is not None:
                for port_element in ports_element.findall('port'):
                    port_info = self.parse_port(port_element)
                    if port_info:
                        ports_data.append(port_info)

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

    def get_service_category(self, port, service_name):
        """Determine service category"""
        port = int(port)

        for category, ports in self.service_ports.items():
            if port in ports:
                return category

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
        elif 'mysql' in service_name_lower:
            return 'mysql'
        elif 'postgres' in service_name_lower:
            return 'postgresql'
        elif 'rdp' in service_name_lower:
            return 'rdp'
        elif 'smb' in service_name_lower:
            return 'smb'
        elif 'snmp' in service_name_lower:
            return 'snmp'

        return 'other'

    def create_service_files(self, hosts_data):
        """Create files by service types"""
        self.logger.info("Creating service-based result files")
        print(f"\nCreating reports...")

        service_groups = defaultdict(list)

        for host in hosts_data:
            for port_info in host['ports']:
                category = self.get_service_category(port_info['port'], port_info['service'])
                service_groups[category].append({
                    'host': host['ip'],
                    'hostname': host['hostname'],
                    'port': port_info['port'],
                    'service': port_info['service'],
                    'product': port_info['product'],
                    'version': port_info['version']
                })

        for category, hosts in service_groups.items():
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

        self.create_summary_file(hosts_data)

    def create_summary_file(self, hosts_data):
        """Create general file with results"""
        summary_file = self.reports_dir / "all_open_ports.txt"

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# GENERAL SCAN REPORT\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" * 60 + "\n\n")

            total_hosts = len(hosts_data)
            total_ports = sum(len(host['ports']) for host in hosts_data)

            f.write(f"Total hosts: {total_hosts}\n")
            f.write(f"Total open ports: {total_ports}\n\n")

            for host in hosts_data:
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

        print(f"{Color.GREEN}[+]{Color.RESET} General report created")

    def generate_markdown_report(self, hosts_data):
        """Generate Markdown report"""
        md_file = self.reports_dir / "scan_report.md"
        
        print(f"{Color.CYAN}[i]{Color.RESET} Generating Markdown report...")
        
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write("# Nmap Scan Report\n\n")
            f.write(f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Scan Duration:** {self.scan_stats['scan_duration']:.1f} seconds\n")
            f.write(f"**Scan Arguments:** `{self.nmap_args}`\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write(f"- **Total Hosts Scanned:** {self.scan_stats['total_hosts']}\n")
            f.write(f"- **Total Open Ports Found:** {self.scan_stats['open_ports']}\n")
            f.write(f"- **Scan Start Time:** {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Scan End Time:** {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if self.scan_stats['services_found']:
                f.write("## Service Distribution\n\n")
                f.write("| Service Category | Count | Percentage |\n")
                f.write("|------------------|-------|------------|\n")
                
                total_ports = self.scan_stats['open_ports']
                for category, count in sorted(self.scan_stats['services_found'].items(), 
                                            key=lambda x: x[1], reverse=True):
                    percentage = (count / total_ports * 100) if total_ports > 0 else 0
                    f.write(f"| {category.capitalize()} | {count} | {percentage:.1f}% |\n")
                f.write("\n")
            
            f.write("## Detailed Findings\n\n")
            
            if hosts_data:
                for host in hosts_data:
                    f.write(f"### {host['ip']}")
                    if host['hostname'] != "Unknown":
                        f.write(f" ({host['hostname']})")
                    f.write("\n\n")
                    
                    if host['ports']:
                        f.write("| Port | Protocol | Service | Version |\n")
                        f.write("|------|----------|---------|---------|\n")
                        
                        for port_info in host['ports']:
                            version_info = ""
                            if port_info['product']:
                                version_info = port_info['product']
                                if port_info['version']:
                                    version_info += f" {port_info['version']}"
                            
                            f.write(f"| {port_info['port']} | {port_info['protocol']} | ")
                            f.write(f"{port_info['service']} | {version_info} |\n")
                    else:
                        f.write("*No open ports found*\n")
                    
                    f.write("\n")
            else:
                f.write("*No hosts with open ports found*\n\n")
            
            f.write("## Security Recommendations\n\n")
            
            critical_services = []
            for host in hosts_data:
                for port_info in host['ports']:
                    port = port_info['port']
                    if port in [22, 3389, 445, 5900, 1433, 3306, 5432]:
                        service_name = port_info['service']
                        version = port_info.get('version', '')
                        critical_services.append({
                            'host': host['ip'],
                            'port': port,
                            'service': service_name,
                            'version': version
                        })
            
            if critical_services:
                f.write("### Critical Services Found\n\n")
                f.write("The following critical services were detected. Ensure they are properly secured:\n\n")
                
                for service in critical_services:
                    f.write(f"- **{service['host']}:{service['port']}** - {service['service']}")
                    if service['version']:
                        f.write(f" ({service['version']})")
                    f.write("\n")
                
                f.write("\n### Recommended Actions:\n\n")
                f.write("1. **SSH (Port 22):** Use key-based authentication, disable root login\n")
                f.write("2. **RDP (Port 3389):** Enable Network Level Authentication, use strong passwords\n")
                f.write("3. **SMB (Port 445):** Disable SMBv1, use latest SMB version\n")
                f.write("4. **Database Ports:** Use firewalls, strong authentication, encryption\n")
            else:
                f.write("No critical services detected in this scan.\n\n")
            
            f.write("## Appendix\n\n")
            f.write("### Scan Parameters\n")
            f.write(f"```\n{self.nmap_args}\n```\n\n")
            
            f.write("### Files Generated\n")
            f.write("- `scan_results.xml` - Raw Nmap XML output\n")
            f.write("- `scan_results.txt` - Raw Nmap text output\n")
            f.write("- `all_open_ports.txt` - Summary of all open ports\n")
            f.write("- Service-specific files (e.g., `web_ports.txt`, `ssh_ports.txt`)\n")
            f.write("- `scan_report.html` - HTML report (if xsltproc available)\n")
            f.write("- `scan_report.md` - This markdown report\n\n")
            
            f.write("### Notes\n")
            f.write("- This report was automatically generated by Nmap Scan Analyzer\n")
            f.write("- Always verify findings manually before taking action\n")
            f.write("- Regular scanning helps maintain security posture\n")
        
        print(f"{Color.GREEN}[+]{Color.RESET} Markdown report created: {md_file}")
        return md_file

    def generate_html_report(self, xml_file):
        """Generate HTML report from XML"""
        self.logger.info("Generating HTML report")
        print(f"\nCreating HTML report...")

        html_output = self.reports_dir / "scan_report.html"
        xslt_file = "/usr/share/nmap/nmap.xsl"

        if not os.path.exists(xslt_file):
            self.logger.warning(f"XSLT file not found: {xslt_file}")
            self.logger.info("Trying to find alternative XSLT file...")

            alternative_paths = [
                "/usr/local/share/nmap/nmap.xsl",
                "/opt/homebrew/share/nmap/nmap.xsl",
                "nmap.xsl"
            ]

            for path in alternative_paths:
                if os.path.exists(path):
                    xslt_file = path
                    break
            else:
                self.logger.error("XSLT file not found.")
                return True

        try:
            cmd = f"xsltproc -o {html_output} {xslt_file} {xml_file}"
            print(f"   {Color.BLUE}[*]{Color.RESET} Converting XML to HTML...")
            
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            
            print(f"   {Color.GREEN}[+]{Color.RESET} HTML report created")
            return True

        except subprocess.CalledProcessError:
            print(f"   {Color.YELLOW}[!]{Color.RESET} Error creating HTML report")
            return False

    def run(self, target, target_type, use_parallel=False, max_workers=4):
        """Main method to start scan and analysis"""
        self.logger.info(f"Starting scan of target: {target}")

        print(f"\n{'='*60}")
        print("STARTING NMAP SCAN")
        print('='*60)
        print(f"Target: {target}")
        print(f"Parameters: {self.nmap_args}")
        print(f"Directory: {self.output_dir}")
        if use_parallel:
            print(f"Parallel Scan: Enabled ({max_workers} workers)")
        print('='*60)

        if use_parallel and target_type in ["cidr", "ip_range", "multi_range"]:
            print(f"{Color.CYAN}[i]{Color.RESET} Using parallel scanning...")
            parallel_scanner = ParallelScanner(self, max_workers)
            hosts_data = parallel_scanner.parallel_scan(target, target_type)
            
            if hosts_data is None:
                xml_file = self.run_nmap_scan(target, target_type)
                if not xml_file:
                    return False
                hosts_data = self.parse_nmap_xml(xml_file)
        else:
            xml_file = self.run_nmap_scan(target, target_type)
            if not xml_file or not xml_file.exists():
                print(f"\n{Color.RED}[-]{Color.RESET} Scan failed")
                return False
            hosts_data = self.parse_nmap_xml(xml_file)

        if not hosts_data:
            print(f"\n{Color.YELLOW}[!]{Color.RESET} No open ports for analysis")
            return False

        self.create_service_files(hosts_data)

        if not use_parallel or (use_parallel and os.path.exists(self.reports_dir / "scan_results.xml")):
            self.generate_html_report(self.reports_dir / "scan_results.xml")
        
        self.generate_markdown_report(hosts_data)

        print(f"\n{'='*60}")
        print(f"{Color.GREEN}[+]{Color.RESET} ANALYSIS COMPLETED!")
        print('='*60)
        self.print_summary()

        return True

    def print_summary(self):
        """Print results summary"""
        print(f"\nRESULTS SUMMARY")
        print('='*60)
        print(f"Results directory: {self.output_dir}")
        print(f"Scan duration: {self.scan_stats['scan_duration']:.1f} seconds")
        print(f"Hosts found: {self.scan_stats['total_hosts']}")
        print(f"Open ports: {self.scan_stats['open_ports']}")
        print(f"\nCreated files:")

        files = list(self.reports_dir.iterdir())
        if files:
            for i, file in enumerate(files, 1):
                if file.is_file():
                    size_kb = file.stat().st_size / 1024
                    print(f"   {i:2d}. {file.name:30} ({size_kb:.1f} KB)")
        else:
            print(f"   {Color.RED}[-]{Color.RESET} No files found")

        print(f"\nReports:")
        print(f"   • HTML: {self.reports_dir}/scan_report.html")
        print(f"   • Markdown: {self.reports_dir}/scan_report.md")
        print(f"   • Text: {self.reports_dir}/all_open_ports.txt")
        print('='*60)

def main():
    parser = argparse.ArgumentParser(
        description='Nmap Scan Analyzer - automates Nmap scanning and results analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 -D scan_results
  %(prog)s 192.168.1.0/24 -D network_scan -p standart
  %(prog)s 192.168.1.1-100 -D range_scan -p quick --parallel
  %(prog)s scanme.nmap.org -D internet_scan -n "-sC -sV"

Profiles: quick, standart, full, udp, stealth, comprehensive
        """
    )

    parser.add_argument('target', help='Scan target (IP, CIDR, IP range, multi-range or domain)')
    parser.add_argument('-D', '--directory', required=True, help='Directory to save results')
    parser.add_argument('-n', '--nmap-args', help='Custom Nmap arguments (overrides profile)')
    parser.add_argument('-p', '--profile', default='standart', 
                       help='Scan profile (quick, standart, full, udp, stealth, comprehensive)')
    parser.add_argument('--parallel', action='store_true', help='Enable parallel scanning')
    parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers (default: 4)')
    parser.add_argument('--list-profiles', action='store_true', help='List available profiles and exit')

    args = parser.parse_args()

    if args.list_profiles:
        print(f"{Color.CYAN}[i]{Color.RESET} Available scan profiles:")
        for profile_name in ScanProfiles.list_profiles():
            print(f"\n{Color.BOLD}{profile_name}:{Color.RESET}")
            profile = ScanProfiles.get_profile(profile_name)
            print(f"  Description: {profile['description']}")
            print(f"  Arguments: {profile['args']}")
            print(f"  Time: {profile['time']}, Stealth: {profile['stealth']}")
        sys.exit(0)

    print_banner()
    
    is_valid, target_type = validate_target(args.target)
    if not is_valid:
        print(f"{Color.RED}[-]{Color.RESET} ERROR: Invalid target format")
        sys.exit(1)

    print(f"{Color.GREEN}[+]{Color.RESET} Target: {args.target} ({target_type})")

    if args.nmap_args:
        nmap_args = args.nmap_args
        print(f"{Color.CYAN}[i]{Color.RESET} Using custom Nmap arguments")
    else:
        if args.profile not in ScanProfiles.PROFILES:
            print(f"{Color.YELLOW}[!]{Color.RESET} Unknown profile '{args.profile}', using 'standart'")
            args.profile = 'standart'
        
        profile = ScanProfiles.get_profile(args.profile)
        nmap_args = profile['args']
        print(f"{Color.CYAN}[i]{Color.RESET} Using '{args.profile}' profile: {profile['description']}")

    hosts_count = calculate_hosts_count(args.target, target_type)
    if hosts_count and hosts_count > 10000:
        print(f"\n{Color.YELLOW}[!]{Color.RESET} WARNING: Large scan detected ({hosts_count} hosts)")
        
        response = input(f"{Color.YELLOW}[?]{Color.RESET} Continue? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print(f"{Color.YELLOW}[!]{Color.RESET} Scan cancelled")
            sys.exit(0)

    scanner = NmapScanner(args.directory, nmap_args)

    success = scanner.run(args.target, target_type, args.parallel, args.workers)

    if success:
        print(f"\n{Color.GREEN}[+]{Color.RESET} SCAN COMPLETED SUCCESSFULLY!")
        print(f"Results saved to: {args.directory}")
        sys.exit(0)
    else:
        print(f"\n{Color.RED}[-]{Color.RESET} SCAN COMPLETED WITH ERRORS")
        print(f"Check log file: {args.directory}/log.txt")
        sys.exit(1)

if __name__ == "__main__":
    if shutil.which("nmap") is None:
        print(f"{Color.RED}[-]{Color.RESET} Error: Nmap not installed")
        print("Install Nmap to use this script")
        sys.exit(1)

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}[!]{Color.RESET} Program interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}[-]{Color.RESET} Error: {e}")
        sys.exit(1)