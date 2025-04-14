import socket
import threading
import time
from queue import Queue
from scapy.all import IP, UDP, TCP, ICMP, sr1, send

# Dictionary for common service identification
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "KERBEROS", 110: "POP3", 111: "RPC", 123: "NTP", 135: "RPC",
    137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    500: "IPSEC", 514: "SYSLOG", 587: "SMTP", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1434: "MSSQL", 1521: "ORACLE",
    1701: "L2TP", 1723: "PPTP", 2049: "NFS", 3306: "MYSQL", 3389: "RDP",
    5060: "SIP", 5061: "SIP", 5432: "POSTGRESQL", 5900: "VNC", 8080: "HTTP-PROXY"
}

# Print lock to prevent thread output collision
print_lock = threading.Lock()
# Store scan results
scan_results = []

def get_service_name(port, protocol):
    """Determine service name from port number"""
    try:
        service = socket.getservbyport(port, protocol)
        return service
    except:
        if port in COMMON_SERVICES:
            return COMMON_SERVICES[port]
        return "unknown"

def grab_banner(ip, port, timeout=2):
    """Try to grab service banner for fingerprinting"""
    banner = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send appropriate request based on common port protocols
            if port == 80 or port == 443 or port == 8080:
                s.send(b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
            elif port == 21:  # FTP
                pass  # Just wait for banner
            elif port == 22:  # SSH
                pass  # Just wait for banner
            elif port == 25 or port == 587:  # SMTP
                pass  # Just wait for banner
            else:
                s.send(b'\r\n')  # Generic request
                
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
    except:
        pass
    return banner

def tcp_connect_scan(ip, port, timeout=1):
    """Perform TCP connect scan on specified port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:  # Port is open
                service = get_service_name(port, "tcp")
                banner = grab_banner(ip, port)
                return True, service, banner
        return False, None, None
    except:
        return False, None, None

def tcp_syn_scan(ip, port, timeout=1):
    """Perform TCP SYN scan (requires admin/root privileges)"""
    try:
        # Send SYN packet
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
        # Wait for response
        response = sr1(syn_packet, timeout=timeout, verbose=0)
        
        if response and response.haslayer(TCP):
            # Check for SYN-ACK response (flag 0x12)
            if response[TCP].flags == 0x12:
                # Send RST to close connection
                rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)
                service = get_service_name(port, "tcp")
                banner = grab_banner(ip, port)
                return True, service, banner
        return False, None, None
    except:
        return False, None, None

def udp_scan(ip, port, timeout=2):
    """Perform UDP scan on specified port"""
    try:
        # Send empty UDP packet
        udp_packet = IP(dst=ip)/UDP(dport=port)
        # Wait for response
        response = sr1(udp_packet, timeout=timeout, verbose=0)
        
        # No response could mean port is open (or filtered)
        if response is None:
            service = get_service_name(port, "udp")
            return "open|filtered", service, None
            
        # ICMP Port Unreachable (type 3, code 3) means port is closed
        elif response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code == 3:
            return "closed", None, None
            
        # Other response typically means port is open
        else:
            service = get_service_name(port, "udp")
            return "open", service, None
    except:
        return "error", None, None

def scan_worker(ip, ports_queue, scan_type):
    """Worker function for threaded scanning"""
    while not ports_queue.empty():
        port = ports_queue.get()
        
        if scan_type == "tcp":
            open_port, service, banner = tcp_connect_scan(ip, port)
            if open_port:
                with print_lock:
                    scan_results.append((port, "tcp", "open", service, banner))
        elif scan_type == "tcp-syn":
            open_port, service, banner = tcp_syn_scan(ip, port)
            if open_port:
                with print_lock:
                    scan_results.append((port, "tcp", "open", service, banner))
        elif scan_type == "udp":
            status, service, banner = udp_scan(ip, port)
            if status == "open" or status == "open|filtered":
                with print_lock:
                    scan_results.append((port, "udp", status, service, banner))
                    
        ports_queue.task_done()

def run_scan(target, port_range, scan_type="tcp", threads=100):
    """Main function to run port scan with multiple threads"""
    start_time = time.time()
    ports_queue = Queue()
    
    # Parse port range
    if "-" in port_range:
        start_port, end_port = map(int, port_range.split("-"))
        port_list = range(start_port, end_port + 1)
    else:
        port_list = [int(p) for p in port_range.split(",")]
    
    # Add ports to queue
    for port in port_list:
        ports_queue.put(port)
    
    print(f"Starting {scan_type} scan on {target} for {len(port_list)} ports")
    
    # Create and start worker threads
    thread_count = min(threads, len(port_list))
    for _ in range(thread_count):
        t = threading.Thread(target=scan_worker, args=(target, ports_queue, scan_type))
        t.daemon = True
        t.start()
    
    # Wait for all ports to be scanned
    ports_queue.join()
    
    # Sort results by port
    scan_results.sort(key=lambda x: x[0])
    
    print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
    print(f"Found {len(scan_results)} open ports\n")
    
    # Display results
    if scan_results:
        print(f"{'PORT':<10} {'PROTOCOL':<10} {'STATE':<15} {'SERVICE':<15} {'BANNER'}")
        print("-" * 80)
        for port, proto, state, service, banner in scan_results:
            banner_truncated = (banner[:50] + '...') if banner and len(banner) > 50 else banner
            print(f"{port:<10} {proto:<10} {state:<15} {service:<15} {banner_truncated}")

def main():
    print("===== Port Scanner Tool =====")
    
    target = input("Enter target IP: ")
    
    print("\nScan type:")
    print("1. TCP Connect scan (reliable, works for any user)")
    print("2. TCP SYN scan (faster, requires administrator/root)")
    print("3. UDP scan (slower, less accurate)")
    scan_choice = input("Enter choice (1-3): ")
    
    scan_types = {
        "1": "tcp",
        "2": "tcp-syn",
        "3": "udp"
    }
    
    scan_type = scan_types.get(scan_choice, "tcp")
    
    port_range = input("Enter port range (e.g. 1-1024 or 21,22,80,443): ")
    if not port_range:
        port_range = "1-1024"  # Default range
    
    threads = input("Enter number of threads (default: 100): ")
    if not threads or not threads.isdigit():
        threads = 100
    else:
        threads = int(threads)
    
    # Run the scan
    run_scan(target, port_range, scan_type, threads)

if _name_ == "_main_":
    main()
