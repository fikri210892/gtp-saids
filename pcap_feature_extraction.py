#!/usr/bin/env python3
"""
Feature Extraction untuk SYN Flood Detection dari PCAP
Dataset: 5GNIDD - SYNflood_BS1.pcapng
"""

import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class PCAPFeatureExtractor:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = None
        self.flows = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'packet_sizes': [],
            'tcp_flags': [],
            'ttls': []
        })
        
    def load_pcap(self):
        """Load PCAP file menggunakan Scapy"""
        print(f"[*] Loading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"[+] Total packets loaded: {len(self.packets)}")
            return True
        except Exception as e:
            print(f"[!] Error loading PCAP: {e}")
            return False
    
    def get_flow_id(self, packet):
        """Generate flow ID (5-tuple)"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto = 6  # TCP
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto = 17  # UDP
            else:
                src_port = 0
                dst_port = 0
                proto = packet[IP].proto
            
            # Bidirectional flow
            flow_id = tuple(sorted([
                (src_ip, src_port),
                (dst_ip, dst_port)
            ]) + [proto])
            
            return flow_id, src_ip, dst_ip, src_port, dst_port, proto
        return None, None, None, None, None, None
    
    def extract_packet_features(self, packet):
        """Ekstrak features dari single packet"""
        features = {}
        
        if IP in packet:
            features['ip_len'] = packet[IP].len
            features['ttl'] = packet[IP].ttl
            features['ip_flags'] = packet[IP].flags
            
            if TCP in packet:
                features['tcp_sport'] = packet[TCP].sport
                features['tcp_dport'] = packet[TCP].dport
                features['tcp_flags'] = packet[TCP].flags
                features['tcp_window'] = packet[TCP].window
                features['tcp_dataofs'] = packet[TCP].dataofs
                
                # TCP Flags individual
                features['flag_syn'] = 1 if packet[TCP].flags & 0x02 else 0
                features['flag_ack'] = 1 if packet[TCP].flags & 0x10 else 0
                features['flag_fin'] = 1 if packet[TCP].flags & 0x01 else 0
                features['flag_rst'] = 1 if packet[TCP].flags & 0x04 else 0
                features['flag_psh'] = 1 if packet[TCP].flags & 0x08 else 0
                features['flag_urg'] = 1 if packet[TCP].flags & 0x20 else 0
                
            elif UDP in packet:
                features['udp_sport'] = packet[UDP].sport
                features['udp_dport'] = packet[UDP].dport
                features['udp_len'] = packet[UDP].len
        
        features['packet_len'] = len(packet)
        
        return features
    
    def build_flows(self):
        """Build flows dari packets"""
        print("[*] Building flows...")
        
        for idx, packet in enumerate(self.packets):
            flow_id, src_ip, dst_ip, src_port, dst_port, proto = self.get_flow_id(packet)
            
            if flow_id:
                self.flows[flow_id]['packets'].append(packet)
                self.flows[flow_id]['timestamps'].append(float(packet.time))
                self.flows[flow_id]['packet_sizes'].append(len(packet))
                
                if IP in packet:
                    self.flows[flow_id]['ttls'].append(packet[IP].ttl)
                
                if TCP in packet:
                    self.flows[flow_id]['tcp_flags'].append(packet[TCP].flags)
                    
                # Simpan info tambahan
                if 'src_ip' not in self.flows[flow_id]:
                    self.flows[flow_id]['src_ip'] = src_ip
                    self.flows[flow_id]['dst_ip'] = dst_ip
                    self.flows[flow_id]['src_port'] = src_port
                    self.flows[flow_id]['dst_port'] = dst_port
                    self.flows[flow_id]['protocol'] = proto
        
        print(f"[+] Total flows created: {len(self.flows)}")
    
    def extract_flow_features(self):
        """Ekstrak features untuk setiap flow"""
        print("[*] Extracting flow features...")
        
        flow_features_list = []
        
        for flow_id, flow_data in self.flows.items():
            features = {}
            
            # Basic flow info
            features['src_ip'] = flow_data['src_ip']
            features['dst_ip'] = flow_data['dst_ip']
            features['src_port'] = flow_data['src_port']
            features['dst_port'] = flow_data['dst_port']
            features['protocol'] = flow_data['protocol']
            
            # Flow statistics
            timestamps = np.array(flow_data['timestamps'])
            packet_sizes = np.array(flow_data['packet_sizes'])
            
            features['flow_duration'] = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
            features['total_packets'] = len(flow_data['packets'])
            features['total_bytes'] = sum(packet_sizes)
            
            # Packet rate
            if features['flow_duration'] > 0:
                features['packets_per_second'] = features['total_packets'] / features['flow_duration']
                features['bytes_per_second'] = features['total_bytes'] / features['flow_duration']
            else:
                features['packets_per_second'] = 0
                features['bytes_per_second'] = 0
            
            # Packet size statistics
            features['packet_size_mean'] = np.mean(packet_sizes)
            features['packet_size_std'] = np.std(packet_sizes)
            features['packet_size_min'] = np.min(packet_sizes)
            features['packet_size_max'] = np.max(packet_sizes)
            
            # Inter-arrival time (IAT)
            if len(timestamps) > 1:
                iat = np.diff(timestamps)
                features['iat_mean'] = np.mean(iat)
                features['iat_std'] = np.std(iat)
                features['iat_min'] = np.min(iat)
                features['iat_max'] = np.max(iat)
            else:
                features['iat_mean'] = 0
                features['iat_std'] = 0
                features['iat_min'] = 0
                features['iat_max'] = 0
            
            # TCP specific features
            if flow_data['protocol'] == 6:  # TCP
                tcp_flags = flow_data['tcp_flags']
                
                # Count TCP flags
                features['syn_count'] = sum(1 for f in tcp_flags if f & 0x02)
                features['ack_count'] = sum(1 for f in tcp_flags if f & 0x10)
                features['fin_count'] = sum(1 for f in tcp_flags if f & 0x01)
                features['rst_count'] = sum(1 for f in tcp_flags if f & 0x04)
                features['psh_count'] = sum(1 for f in tcp_flags if f & 0x08)
                features['urg_count'] = sum(1 for f in tcp_flags if f & 0x20)
                
                # SYN flood indicators
                features['syn_ratio'] = features['syn_count'] / features['total_packets']
                features['syn_ack_ratio'] = features['ack_count'] / features['total_packets']
                
                # Check for incomplete handshake (SYN without SYN-ACK)
                features['incomplete_handshake'] = 1 if features['syn_count'] > 0 and features['ack_count'] == 0 else 0
                
            else:
                features['syn_count'] = 0
                features['ack_count'] = 0
                features['fin_count'] = 0
                features['rst_count'] = 0
                features['psh_count'] = 0
                features['urg_count'] = 0
                features['syn_ratio'] = 0
                features['syn_ack_ratio'] = 0
                features['incomplete_handshake'] = 0
            
            # TTL statistics
            if flow_data['ttls']:
                features['ttl_mean'] = np.mean(flow_data['ttls'])
                features['ttl_std'] = np.std(flow_data['ttls'])
            else:
                features['ttl_mean'] = 0
                features['ttl_std'] = 0
            
            flow_features_list.append(features)
        
        return pd.DataFrame(flow_features_list)
    
    def extract_time_window_features(self, window_size=1.0):
        """Ekstrak features per time window (agregasi temporal)"""
        print(f"[*] Extracting time-window features (window={window_size}s)...")
        
        if not self.packets:
            return None
        
        # Get time range
        start_time = float(self.packets[0].time)
        end_time = float(self.packets[-1].time)
        
        windows = []
        current_time = start_time
        
        while current_time < end_time:
            window_end = current_time + window_size
            
            window_packets = [p for p in self.packets 
                            if current_time <= float(p.time) < window_end]
            
            if window_packets:
                features = self.calculate_window_features(window_packets, current_time)
                windows.append(features)
            
            current_time = window_end
        
        return pd.DataFrame(windows)
    
    def calculate_window_features(self, packets, window_start):
        """Hitung features untuk satu time window"""
        features = {}
        features['window_start'] = window_start
        features['total_packets'] = len(packets)
        
        # Count by protocol
        tcp_count = sum(1 for p in packets if TCP in p)
        udp_count = sum(1 for p in packets if UDP in p)
        icmp_count = sum(1 for p in packets if ICMP in p)
        
        features['tcp_packets'] = tcp_count
        features['udp_packets'] = udp_count
        features['icmp_packets'] = icmp_count
        
        # TCP flags analysis
        syn_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x02)
        ack_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x10)
        syn_ack_count = sum(1 for p in packets if TCP in p and (p[TCP].flags & 0x12) == 0x12)
        
        features['syn_packets'] = syn_count
        features['ack_packets'] = ack_count
        features['syn_ack_packets'] = syn_ack_count
        
        # SYN flood indicators
        features['syn_ratio'] = syn_count / len(packets) if len(packets) > 0 else 0
        features['syn_ack_ratio'] = syn_ack_count / syn_count if syn_count > 0 else 0
        
        # Unique IPs
        src_ips = set()
        dst_ips = set()
        for p in packets:
            if IP in p:
                src_ips.add(p[IP].src)
                dst_ips.add(p[IP].dst)
        
        features['unique_src_ips'] = len(src_ips)
        features['unique_dst_ips'] = len(dst_ips)
        
        # Packet sizes
        packet_sizes = [len(p) for p in packets]
        features['total_bytes'] = sum(packet_sizes)
        features['avg_packet_size'] = np.mean(packet_sizes)
        features['std_packet_size'] = np.std(packet_sizes)
        
        return features
    
    def detect_syn_flood(self, df, threshold_syn_ratio=0.7):
        """Simple detection: label berdasarkan SYN ratio"""
        df['is_attack'] = (df['syn_ratio'] > threshold_syn_ratio).astype(int)
        return df
    
    def run_extraction(self, output_prefix='features'):
        """Jalankan semua proses extraction"""
        if not self.load_pcap():
            return None
        
        # Flow-based features
        self.build_flows()
        flow_df = self.extract_flow_features()
        flow_df = self.detect_syn_flood(flow_df)
        
        print(f"\n[+] Flow Features Shape: {flow_df.shape}")
        print(f"[+] Columns: {list(flow_df.columns)}")
        
        # Time-window features
        window_df = self.extract_time_window_features(window_size=1.0)
        
        if window_df is not None:
            window_df = self.detect_syn_flood(window_df)
            print(f"[+] Window Features Shape: {window_df.shape}")
        
        # Save to CSV
        flow_output = f'outputs/{output_prefix}_flow_based.csv'
        flow_df.to_csv(flow_output, index=False)
        print(f"\n[+] Flow-based features saved: {flow_output}")
        
        if window_df is not None:
            window_output = f'outputs/{output_prefix}_time_window.csv'
            window_df.to_csv(window_output, index=False)
            print(f"[+] Time-window features saved: {window_output}")
        
        # Display summary statistics
        self.display_summary(flow_df, window_df)
        
        return flow_df, window_df
    
    def display_summary(self, flow_df, window_df):
        """Display summary statistics"""
        print("\n" + "="*70)
        print("SUMMARY STATISTICS")
        print("="*70)
        
        print("\n--- Flow-based Features ---")
        print(f"Total flows: {len(flow_df)}")
        print(f"Flows labeled as attack: {flow_df['is_attack'].sum()}")
        print(f"Attack ratio: {flow_df['is_attack'].mean():.2%}")
        
        print("\nSYN Flood Indicators:")
        print(flow_df[['syn_count', 'ack_count', 'syn_ratio', 'incomplete_handshake']].describe())
        
        if window_df is not None:
            print("\n--- Time-window Features ---")
            print(f"Total windows: {len(window_df)}")
            print(f"Windows labeled as attack: {window_df['is_attack'].sum()}")
            print(f"Attack ratio: {window_df['is_attack'].mean():.2%}")
            
            print("\nWindow Statistics:")
            print(window_df[['syn_packets', 'syn_ratio', 'unique_src_ips']].describe())


def main():
    # Konfigurasi
    pcap_file = '/home/ubuntu/SYNflood_BS1.pcapng'
    
    print("="*70)
    print("PCAP FEATURE EXTRACTION FOR SYN FLOOD DETECTION")
    print("="*70)
    print(f"Input file: {pcap_file}\n")
    
    # Inisialisasi extractor
    extractor = PCAPFeatureExtractor(pcap_file)
    
    # Jalankan extraction
    flow_df, window_df = extractor.run_extraction(output_prefix='synflood_bs1')
    
    print("\n" + "="*70)
    print("EXTRACTION COMPLETE!")
    print("="*70)
    print("\nYou can now use these features for:")
    print("  1. Machine Learning (Classification, Anomaly Detection)")
    print("  2. Statistical Analysis")
    print("  3. Visualization")
    print("  4. Network Behavior Analysis")


if __name__ == "__main__":
    main()
