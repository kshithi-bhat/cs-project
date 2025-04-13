import argparse
import socket
import json
import csv
from threading import Thread, Lock
from queue import Queue
from scapy.all import ICMP, IP, UDP, TCP, sr1, sr
from scapy.error import Scapy_Exception
import nmap

print_lock = Lock()
results = []


def tcp_scan(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def udp_scan(target, port, timeout=1):
    try:
        packet = IP(dst=target) / UDP(dport=port)
        response = sr1(packet, timeout=timeout, verbose=0)
        if response is None:
            return "open|filtered"
        elif response.haslayer(ICMP):
            return "closed"
        return "open"
    except Scapy_Exception:
        return "error"


def get_service(target, port, proto):
    try:
        # Try banner grabbing first
        if proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            sock.send(b'GET / HTTP/1.1\r\n\r\n')
            banner = sock.recv(1024).decode().strip()
            sock.close()
            if banner: return banner.split('\n')[0]
    except:
        pass

    # Use nmap for service detection
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments=f'-sV -p {port} --version-intensity 3')
        return scanner[target][proto][port]['name']
    except:
        return "unknown"


def worker(target, ports, scan_type, timeout):
    while True:
        port = ports.get()
        if scan_type == 'tcp':
            status = tcp_scan(target, port, timeout)
            proto = 'tcp'
        else:
            status = udp_scan(target, port, timeout)
            proto = 'udp'

        # Debugging line: Print the scanning results
        print(f"Scanned {port}: {status}")  # Add this line to see the result in the console

        if status in [True, "open", "open|filtered"]:
            service = get_service(target, port, proto)
            with print_lock:
                results.append({
                    'port': port,
                    'protocol': proto,
                    'status': 'open' if status is True else status,
                    'service': service
                })
        ports.task_done()


def main():
    parser = argparse.ArgumentParser(description='Advanced Port Scanner with Service Detection')
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Port range (e.g., 1-100) or list (e.g., 21,22,80)')
    parser.add_argument('-t', '--type', choices=['tcp', 'udp'], default='tcp',
                        help='Scan type (default: tcp)')
    parser.add_argument('-T', '--threads', type=int, default=100,
                        help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output', choices=['csv', 'json'], help='Output format')
    args = parser.parse_args()

    # Parse ports
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    else:
        ports = list(map(int, args.ports.split(',')))

    ports_queue = Queue()
    for port in ports:
        ports_queue.put(port)

    # Starting the worker threads
    for _ in range(args.threads):
        Thread(target=worker, args=(args.target, ports_queue, args.type, 1), daemon=True).start()

    ports_queue.join()

    # Debugging line: Print the results list
    print("Results list:")
    print(results)  # This will print the results list to the console

    # Display results
    print(f"\nScan results for {args.target}:")
    print("PORT\tPROTOCOL\tSTATUS\tSERVICE")
    for result in results:
        print(f"{result['port']}\t{result['protocol']}\t\t{result['status']}\t{result['service']}")

    # Save output
    if args.output:
        filename = f"scan_{args.target}.{args.output}"
        with open(filename, 'w') as f:
            if args.output == 'json':
                json.dump(results, f, indent=4)  # Add indent for better readability
            else:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"\nResults saved to {filename}")


if __name__ == "__main__":
    main()
