import socket
import struct
import subprocess
from scapy.all import *

def get_ttl(ip):
    try:
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply:
            return reply.ttl
    except Exception as e:
        print(f"Error: {e}")
    return None

def get_window_size(ip):
    try:
        pkt = IP(dst=ip) / TCP(dport=80, flags='S')
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply and reply.haslayer(TCP):
            return reply[TCP].window
    except Exception as e:
        print(f"Error: {e}")
    return None

def banner_grab(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = s.recv(1024).decode()
        s.close()
        return banner.strip()
    except:
        return None

def os_guess(ttl, window_size):
    if ttl and window_size:
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Network Device"
    return "Unknown"

def nmap_os_scan(ip):
    try:
        result = subprocess.run(["nmap", "-O", ip], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Nmap not found. Install it to use this feature."

def fingerprint_os(ip):
    print(f"Fingerprinting OS for {ip}...")
    ttl = get_ttl(ip)
    window_size = get_window_size(ip)
    banner = banner_grab(ip, 80)  # Checking HTTP banner
    nmap_result = nmap_os_scan(ip)
    
    print(f"TTL: {ttl}, Window Size: {window_size}")
    guessed_os = os_guess(ttl, window_size)
    print(f"OS Guess: {guessed_os}")
    
    if banner:
        print(f"Banner: {banner}")
    print("\nNmap Scan Result:")
    print(nmap_result)

if __name__ == "__main__":
    target_ip = input("Enter the target IP: ")
    fingerprint_os(target_ip)
