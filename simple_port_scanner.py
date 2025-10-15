# simple_port_scanner.py
# A fast, multi-threaded TCP Port Scanner with Banner Grabbing, HTTP Probing, and basic Vulnerability Checking.
# This script is designed for professional use and robust error handling.

import socket
import sys
import argparse
from datetime import datetime
import concurrent.futures

# --- ANSI Color Codes for "Cybersecurity Theme" ---
RED = '\033[91m'      # Critical/Vulnerable
GREEN = '\033[92m'    # Open/Clean
YELLOW = '\033[93m'   # Warnings/Progress
CYAN = '\033[96m'     # Headers
RESET = '\033[0m'     # Reset color

# --- Configuration ---
# Timeout for initial connection attempts in seconds (faster scan = lower timeout).
SOCKET_TIMEOUT = 0.5 
# Default Maximum number of threads to run concurrently.
DEFAULT_WORKERS = 100

# Dictionary mapping common port numbers to service names for easy readability.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-ALT"
}

# Simple, hardcoded database of known vulnerable banners/versions for demonstration.
KNOWN_VULNERABLE_BANNERS = {
    "apache/2.2.8": "EOL/Unsupported Apache version, known XSS/DoS vulnerabilities.",
    "vsftpd 2.3.4": "Highly critical backdoor vulnerability (CVE-2011-2523).",
    "pure-ftpd": "Older versions have authentication bypass flaws.",
    "openvpn 2.4.0": "Older versions have memory corruption/DoS issues (CVE-2017-7484).",
    "microsoft-iis/6.0": "IIS 6.0 is EOL and highly vulnerable."
}

def get_service_name(port):
    """Retrieves the common name for a given port."""
    return COMMON_PORTS.get(port, 'Unknown')

def check_vulnerability(banner):
    """
    Checks the captured banner against a list of known vulnerable versions/keywords.
    Returns a vulnerability description string if a match is found, otherwise None.
    """
    if not banner or banner == "No banner received (timeout).":
        return None

    banner_lower = banner.lower()
    for vulnerable_keyword, description in KNOWN_VULNERABLE_BANNERS.items():
        if vulnerable_keyword.lower() in banner_lower:
            return description
            
    return None

def http_probe(s, target_ip, port):
    """Attempts a basic HTTP GET request to get web server banner."""
    try:
        # Send minimal HTTP GET request
        http_request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
        s.send(http_request.encode())
        
        s.settimeout(1.0) # Longer timeout for response
        response = s.recv(1024).decode('utf-8', errors='ignore')
        
        # Look for the Server header in the response
        server_line = next((line for line in response.split('\n') if line.lower().startswith('server:')), None)
        
        if server_line:
            return server_line.strip()
            
    except Exception:
        pass
    return None

def scan_port(target_ip, port):
    """
    Core function: Connects, grabs banner (or probes HTTP), and checks for vulnerabilities.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT)
    
    result = {
        'port': port, 
        'status': 'closed', 
        'service': get_service_name(port), 
        'banner': None,
        'vulnerability': None
    }
    
    try:
        # Attempt to connect to the target (0 means success)
        connection_result = s.connect_ex((target_ip, port))
        
        if connection_result == 0:
            result['status'] = 'open'
            
            # --- Banner Grabbing / HTTP Probing ---
            banner_string = None
            
            if port in (80, 443, 8080):
                banner_string = http_probe(s, target_ip, port)
            
            # If not an HTTP port, or HTTP probe failed, try generic banner grab
            if not banner_string:
                try:
                    s.settimeout(0.2) 
                    banner_data = s.recv(1024)
                    banner_string = banner_data.decode('utf-8', errors='ignore').strip().split('\n')[0]
                except socket.timeout:
                    banner_string = "No banner received (timeout)."
                except Exception:
                    banner_string = "Error receiving banner."

            if banner_string:
                result['banner'] = banner_string
                # --- Vulnerability Check Integration ---
                result['vulnerability'] = check_vulnerability(banner_string)
                
    except socket.error:
        # This typically indicates a network error or host is down/aggressively filtering
        result['status'] = 'error'
    finally:
        s.close()
        
    return result

def main():
    """
    Handles CLI arguments, orchestrates the multi-threaded scanning process, 
    and prints the colorized, detailed report.
    """
    # 1. Setup Argparse for professional CLI
    parser = argparse.ArgumentParser(
        description=f"{CYAN}Python Vulnerability Port Scanner (MADE BY ARON :) - Professional Version{RESET}",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
    )
    parser.add_argument('target', help='IP address or hostname to scan (e.g., 127.0.0.1)')
    parser.add_argument('-p', '--ports', required=True, help='Port range to scan (e.g., 1-1024 or 21,22,80)')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, 
                        help=f'Number of concurrent threads (default: {DEFAULT_WORKERS})')

    args = parser.parse_args()
    
    # 2. Parse Ports
    ports_to_scan = set()
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
            if start_port > end_port or start_port < 1 or end_port > 65535:
                 print(f"{RED}[!] Error: Invalid port range ({args.ports}). Must be 1-65535.{RESET}")
                 sys.exit(1)
            ports_to_scan = set(range(start_port, end_port + 1))
        else:
            ports_to_scan = set(map(int, args.ports.split(',')))
    except Exception:
        print(f"{RED}[!] Error: Invalid port format. Use 1-1024 or 21,22,80.{RESET}")
        sys.exit(1)


    # 3. Resolve Target IP
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"\n{RED}[!] Error: Hostname '{args.target}' could not be resolved.{RESET}")
        sys.exit(1)

    # 4. Scanning Setup
    print(CYAN + "=" * 80 + RESET)
    print(f"{CYAN}VULNERABILITY PORT SCANNER ( MADE BY ARON :){RESET}")
    print(CYAN + "=" * 80 + RESET)
    print(f"{YELLOW}[+] Target: {target_ip} ({args.target})")
    print(f"[+] Ports: {len(ports_to_scan)} | Threads: {args.workers}{RESET}")
    print("-" * 80)
    
    open_ports_data = []
    t1 = datetime.now()

    # 5. Start the Multi-threaded Scan
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_port = {executor.submit(scan_port, target_ip, port): port for port in ports_to_scan}
            
            total_ports = len(ports_to_scan)
            for i, future in enumerate(concurrent.futures.as_completed(future_to_port)):
                result = future.result()

                # Basic progress tracking
                sys.stdout.write(f"\r{YELLOW}Scanning... [{i + 1}/{total_ports}] ports checked.{RESET}")
                sys.stdout.flush()

                if result['status'] == 'open':
                    open_ports_data.append(result)
                    
                    service_info = f"({result['service']})"
                    
                    if result['vulnerability']:
                        # Highlight vulnerable ports in RED
                        print(f"\r{RED}[!! VULNERABLE !!] Port {result['port']:<5} {service_info:<15} -> {result['banner']}")
                        print(f"                                 L-- VULN: {result['vulnerability']}{RESET}")
                    else:
                        # Highlight clean/open ports in GREEN
                        banner_info = f" -> Banner: {result['banner']}" if result['banner'] else ""
                        print(f"\r{GREEN}[*** OPEN ***] Port {result['port']:<5} {service_info:<15} {banner_info}{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user. Stopping workers...{RESET}")
    except Exception as e:
        print(f"\n{RED}[!!] An unexpected error occurred: {e}{RESET}")
        
    # 6. Final summary and detailed report
    t2 = datetime.now()
    total_time = t2 - t1
    
    print("\n" + CYAN + "=" * 80 + RESET)
    print(f"{CYAN}Scan Complete. Found {len(open_ports_data)} open ports. Total time: {total_time}{RESET}")
    print(CYAN + "=" * 80 + RESET)
    
    if open_ports_data:
        print("\n" + YELLOW + "--- DETAILED VULNERABILITY REPORT ---" + RESET)
        for data in open_ports_data:
            color = RED if data['vulnerability'] else GREEN
            v_status = f"{RED}VULNERABLE: {data['vulnerability']}{RESET}" if data['vulnerability'] else f"{GREEN}CLEAN (Limited Database){RESET}"
            
            print(f"\n{color}Port: {data['port']:<5} | Service: {data['service']:<15} | Banner: {data['banner'] if data['banner'] else 'N/A'}")
            print(f"                                   | Status: {v_status}")
        print("-" * 80)


if __name__ == "__main__":
    main()
# simple_port_scanner.py
