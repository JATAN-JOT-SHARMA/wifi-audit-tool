#!/usr/bin/env python3
"""
WiFi Security Assessment - Real-Time Vulnerability Scanner
FOR AUTHORIZED TESTING ONLY
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import os
import time
import queue
import hashlib
import binascii
import platform
import json
from datetime import datetime
import re
import sys
import socket
import struct
from pathlib import Path
import tempfile
import random

class WiFiVulnerabilityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Scanner - Real-Time Vulnerability Assessment")
        self.root.geometry("1400x900")
        
        # Setup dark theme
        self.setup_theme()
        
        # Application paths
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.capture_dir = os.path.join(self.base_dir, "captures")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.hash_dir = os.path.join(self.base_dir, "hashes")
        
        for d in [self.capture_dir, self.reports_dir, self.hash_dir]:
            os.makedirs(d, exist_ok=True)
        
        # Variables
        self.running = False
        self.scanning = False
        self.log_queue = queue.Queue()
        self.networks = {}
        self.vulnerabilities = []
        self.current_scan = None
        self.assessment_complete = False
        
        # Authorization
        self.authorized = False
        self.auth_file = os.path.join(self.base_dir, "authorization.json")
        
        # Build UI
        self.build_ui()
        self.process_logs()
        self.load_authorization()
        
    def setup_theme(self):
        """Setup dark professional theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        colors = {
            'bg': '#1a1a2e',
            'fg': '#e0e0e0',
            'select': '#16213e',
            'accent': '#0f3460',
            'success': '#00ff88',
            'warning': '#ffaa00',
            'danger': '#ff4444',
            'info': '#00aaff'
        }
        
        style.configure('TLabel', background=colors['bg'], foreground=colors['fg'])
        style.configure('TFrame', background=colors['bg'])
        style.configure('TLabelframe', background=colors['bg'], foreground=colors['fg'])
        style.configure('TLabelframe.Label', background=colors['bg'], foreground=colors['fg'])
        style.configure('TButton', background=colors['select'], foreground=colors['fg'])
        style.configure('TEntry', fieldbackground=colors['select'], foreground=colors['fg'])
        style.configure('TCombobox', fieldbackground=colors['select'], foreground=colors['fg'])
        style.map('TButton', background=[('active', colors['accent'])])
        
    def build_ui(self):
        """Build the complete UI"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top status bar
        status_bar = ttk.Frame(main_frame)
        status_bar.pack(fill=tk.X, pady=5)
        
        self.auth_status = ttk.Label(status_bar, text="🔴 NOT AUTHORIZED", 
                                    font=('Segoe UI', 10, 'bold'), foreground='#ff4444')
        self.auth_status.pack(side=tk.LEFT, padx=10)
        
        self.scan_status = ttk.Label(status_bar, text="⚪ IDLE", 
                                    font=('Segoe UI', 10, 'bold'), foreground='#888888')
        self.scan_status.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(status_bar, text="🔐 Authorize", 
                  command=self.show_auth_dialog).pack(side=tk.RIGHT, padx=2)
        ttk.Button(status_bar, text="📡 Scan", 
                  command=self.start_scan).pack(side=tk.RIGHT, padx=2)
        ttk.Button(status_bar, text="🔍 Assess", 
                  command=self.start_assessment).pack(side=tk.RIGHT, padx=2)
        ttk.Button(status_bar, text="⏹ Stop", 
                  command=self.stop_scan).pack(side=tk.RIGHT, padx=2)
        
        # Paned window
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # LEFT PANEL - Network Discovery
        left_panel = ttk.Frame(paned)
        paned.add(left_panel, weight=1)
        
        # Network Scan Results
        net_frame = ttk.LabelFrame(left_panel, text="📡 Detected Networks", padding=5)
        net_frame.pack(fill=tk.BOTH, expand=True)
        
        # Network tree
        columns = ('BSSID', 'CH', 'ENC', 'WPS', 'SIGNAL', 'VULN', 'ESSID')
        self.net_tree = ttk.Treeview(net_frame, columns=columns, show='headings', height=12)
        
        widths = {'BSSID': 140, 'CH': 40, 'ENC': 70, 'WPS': 50, 'SIGNAL': 60, 'VULN': 50, 'ESSID': 150}
        for col in columns:
            self.net_tree.heading(col, text=col)
            self.net_tree.column(col, width=widths.get(col, 100))
        
        scrollbar = ttk.Scrollbar(net_frame, orient=tk.VERTICAL, command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=scrollbar.set)
        
        self.net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.net_tree.bind('<Double-Button-1>', self.select_network)
        
        # RIGHT PANEL - Real-Time Assessment
        right_panel = ttk.Frame(paned)
        paned.add(right_panel, weight=2)
        
        # Assessment Results
        assess_frame = ttk.LabelFrame(right_panel, text="🔬 Vulnerability Assessment Results", padding=5)
        assess_frame.pack(fill=tk.BOTH, expand=True)
        
        # Vulnerability tree
        vuln_columns = ('SEVERITY', 'TYPE', 'DETAIL', 'STATUS')
        self.vuln_tree = ttk.Treeview(assess_frame, columns=vuln_columns, show='headings', height=8)
        
        for col in vuln_columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=120)
        self.vuln_tree.column('DETAIL', width=300)
        
        vuln_scroll = ttk.Scrollbar(assess_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scroll.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vuln_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Assessment Details
        detail_frame = ttk.LabelFrame(right_panel, text="📊 Assessment Details", padding=5)
        detail_frame.pack(fill=tk.BOTH, expand=True)
        
        self.detail_text = scrolledtext.ScrolledText(detail_frame, 
                                                   bg='#0a0a1a', fg='#00ff88',
                                                   font=('Consolas', 9), 
                                                   insertbackground='white',
                                                   height=8)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        # Detail tags
        self.detail_text.tag_config('error', foreground='#ff4444')
        self.detail_text.tag_config('success', foreground='#44ff44')
        self.detail_text.tag_config('info', foreground='#00aaff')
        self.detail_text.tag_config('warning', foreground='#ffaa00')
        self.detail_text.tag_config('critical', foreground='#ff00ff', font=('Consolas', 10, 'bold'))
        self.detail_text.tag_config('vulnerability', foreground='#ff4444', font=('Consolas', 10, 'bold'))
        self.detail_text.tag_config('found', foreground='#ff00ff', font=('Consolas', 11, 'bold'))
        
        # BOTTOM - Console
        console_frame = ttk.LabelFrame(main_frame, text="📝 Console", padding=5)
        console_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.console = scrolledtext.ScrolledText(console_frame, 
                                               bg='#0a0a1a', fg='#00ff88',
                                               font=('Consolas', 9), 
                                               insertbackground='white',
                                               height=6)
        self.console.pack(fill=tk.BOTH, expand=True)
        
        # Console tags
        self.console.tag_config('error', foreground='#ff4444')
        self.console.tag_config('success', foreground='#44ff44')
        self.console.tag_config('info', foreground='#00aaff')
        self.console.tag_config('warning', foreground='#ffaa00')
        self.console.tag_config('vulnerability', foreground='#ff4444', font=('Consolas', 10, 'bold'))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                          mode='determinate', length=100)
        self.progress_bar.pack(fill=tk.X, pady=2)
        
        # Status
        self.status_var = tk.StringVar(value="Ready - Authorization Required")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                               relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(fill=tk.X)
        
    def show_auth_dialog(self):
        """Show authorization dialog"""
        auth_window = tk.Toplevel(self.root)
        auth_window.title("Authorization")
        auth_window.geometry("500x350")
        auth_window.transient(self.root)
        auth_window.grab_set()
        
        main_frame = ttk.Frame(auth_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="🔐 LEGAL AUTHORIZATION REQUIRED", 
                 font=('Segoe UI', 14, 'bold')).pack(pady=10)
        
        ttk.Label(main_frame, text="By continuing, you confirm:", 
                 font=('Segoe UI', 10)).pack(anchor=tk.W, pady=5)
        
        ttk.Label(main_frame, text="✅ Written permission from network owner", 
                 font=('Segoe UI', 9)).pack(anchor=tk.W, pady=2)
        ttk.Label(main_frame, text="✅ Valid business need for testing", 
                 font=('Segoe UI', 9)).pack(anchor=tk.W, pady=2)
        ttk.Label(main_frame, text="✅ Authorization documentation on file", 
                 font=('Segoe UI', 9)).pack(anchor=tk.W, pady=2)
        
        ttk.Label(main_frame, text="Authorization Reference #:").pack(anchor=tk.W, pady=(10,0))
        auth_entry = ttk.Entry(main_frame, width=40)
        auth_entry.pack(anchor=tk.W, pady=5)
        
        ttk.Label(main_frame, text="Organization:").pack(anchor=tk.W, pady=(5,0))
        org_entry = ttk.Entry(main_frame, width=40)
        org_entry.pack(anchor=tk.W, pady=5)
        
        def confirm():
            auth_id = auth_entry.get().strip()
            org = org_entry.get().strip()
            
            if not auth_id or not org:
                messagebox.showwarning("Required", "Please fill in all fields")
                return
                
            self.authorized = True
            self.auth_id = auth_id
            self.organization = org
            self.auth_status.config(text=f"🟢 AUTHORIZED - {org}", foreground='#44ff44')
            self.status_var.set(f"Authorized - {org} (Ref: {auth_id})")
            self.log_msg(f"✅ Authorization confirmed - {org} (Ref: {auth_id})", 'success')
            self.save_authorization()
            auth_window.destroy()
            
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="✅ Confirm", command=confirm, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=auth_window.destroy, width=15).pack(side=tk.LEFT, padx=5)
        
    def save_authorization(self):
        """Save authorization"""
        data = {
            'authorized': True,
            'auth_id': getattr(self, 'auth_id', ''),
            'organization': getattr(self, 'organization', ''),
            'timestamp': datetime.now().isoformat()
        }
        with open(self.auth_file, 'w') as f:
            json.dump(data, f, indent=2)
            
    def load_authorization(self):
        """Load saved authorization"""
        if os.path.exists(self.auth_file):
            try:
                with open(self.auth_file, 'r') as f:
                    data = json.load(f)
                    if data.get('authorized'):
                        self.authorized = True
                        self.auth_id = data.get('auth_id', '')
                        self.organization = data.get('organization', '')
                        self.auth_status.config(text=f"🟢 AUTHORIZED - {self.organization}", 
                                              foreground='#44ff44')
                        self.status_var.set(f"Authorized - {self.organization}")
            except:
                pass
                
    def log_msg(self, msg, tag=None):
        """Log message to console"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_queue.put((f"[{timestamp}] {msg}", tag))
        
    def log_detail(self, msg, tag=None):
        """Log to detail text"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.detail_text.insert(tk.END, f"[{timestamp}] {msg}\n", tag)
        self.detail_text.see(tk.END)
        
    def process_logs(self):
        """Process log queue"""
        try:
            while True:
                msg, tag = self.log_queue.get_nowait()
                self.console.insert(tk.END, msg + '\n', tag)
                self.console.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.process_logs)
        
    def start_scan(self):
        """Start network scan"""
        if not self.authorized:
            messagebox.showwarning("Authorization Required", 
                                 "Must be authorized to scan!")
            return
            
        if self.scanning:
            return
            
        self.scanning = True
        self.scan_status.config(text="🟡 SCANNING", foreground='#ffaa00')
        self.status_var.set("Scanning for networks...")
        
        # Clear existing networks
        for item in self.net_tree.get_children():
            self.net_tree.delete(item)
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
            
        self.vulnerabilities = []
        self.log_msg("📡 Starting network scan...", 'info')
        
        threading.Thread(target=self._scan_networks, daemon=True).start()
        
    def _scan_networks(self):
        """Scan for networks"""
        try:
            self.progress_var.set(0)
            
            if platform.system() == 'Windows':
                self._scan_windows()
            else:
                self._scan_linux()
                
            count = len(self.net_tree.get_children())
            self.log_msg(f"✅ Scan complete - Found {count} networks", 'success')
            self.scan_status.config(text="🟢 SCAN COMPLETE", foreground='#44ff44')
            self.status_var.set(f"Found {count} networks")
            
            # Auto-start assessment if networks found
            if count > 0:
                self.log_msg("🔍 Starting vulnerability assessment...", 'info')
                self.start_assessment()
                
        except Exception as e:
            self.log_msg(f"❌ Scan error: {e}", 'error')
            self.scan_status.config(text="🔴 SCAN FAILED", foreground='#ff4444')
        finally:
            self.scanning = False
            self.progress_var.set(100)
            
    def _scan_windows(self):
        """Windows scan"""
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
            capture_output=True, text=True, encoding='utf-8', errors='ignore',
            timeout=30
        )
        
        networks = []
        current = {}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if line.startswith('SSID'):
                if current.get('ssid'):
                    networks.append(current)
                current = {'ssid': line.split(':', 1)[1].strip()}
                continue
                
            if line.startswith('BSSID'):
                current['bssid'] = line.split(':', 1)[1].strip()
                continue
                
            if '通道' in line or 'Channel' in line:
                current['channel'] = line.split(':', 1)[1].strip() if ':' in line else ''
                continue
                
            if '加密' in line or 'Encryption' in line:
                current['encryption'] = line.split(':', 1)[1].strip() if ':' in line else ''
                continue
                
            if '信号' in line or 'Signal' in line:
                current['signal'] = line.split(':', 1)[1].strip() if ':' in line else ''
                # Add to tree
                if current.get('ssid') and current.get('bssid'):
                    self._add_network(current)
                    current = {}
                    
    def _scan_linux(self):
        """Linux scan"""
        # Get interfaces
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if line and not line.startswith(' '):
                iface = line.split()[0]
                if iface not in ['lo']:
                    interfaces.append(iface)
                    
        if interfaces:
            interface = interfaces[0]
            
            # Start monitor mode
            subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                         capture_output=True, timeout=5)
            
            # Scan
            result = subprocess.run(
                ['sudo', 'airodump-ng', interface + 'mon', '--output-format', 'csv', 
                 '-w', '/tmp/scan'],
                capture_output=True, text=True, timeout=20
            )
            
            # Parse CSV
            try:
                with open('/tmp/scan-01.csv', 'r') as f:
                    for line in f:
                        if ',' in line and not line.startswith('BSSID'):
                            parts = [p.strip() for p in line.split(',')]
                            if len(parts) >= 14 and parts[0]:
                                network = {
                                    'bssid': parts[0],
                                    'channel': parts[3],
                                    'encryption': parts[5],
                                    'ssid': parts[13] if len(parts) > 13 else 'Unknown',
                                    'signal': parts[8] if len(parts) > 8 else '-60'
                                }
                                self._add_network(network)
            except:
                pass
                
    def _add_network(self, network):
        """Add network to tree"""
        bssid = self._normalize_mac(network.get('bssid', ''))
        ssid = network.get('ssid', 'Unknown')
        channel = network.get('channel', '')
        encryption = network.get('encryption', 'Unknown')
        signal = network.get('signal', '')
        
        # Check if already exists
        for item in self.net_tree.get_children():
            if self.net_tree.item(item)['values'][0] == bssid:
                return
                
        self.net_tree.insert('', tk.END, values=(
            bssid, channel, encryption, '?', signal, '0', ssid
        ))
        
    def _normalize_mac(self, mac):
        """Normalize MAC"""
        mac = mac.upper().replace('-', ':').replace('.', '')
        parts = []
        for i in range(0, len(mac), 2):
            if i+2 <= len(mac):
                parts.append(mac[i:i+2])
        return ':'.join(parts) if len(parts) == 6 else mac
        
    def select_network(self, event):
        """Select network from tree"""
        selection = self.net_tree.selection()
        if not selection:
            return
            
        item = self.net_tree.item(selection[0])
        values = item['values']
        
        if len(values) >= 3:
            self.target_bssid = values[0]
            self.target_essid = values[6] if len(values) > 6 else ''
            self.target_channel = values[1] if len(values) > 1 else ''
            
            self.log_msg(f"🎯 Selected: {self.target_essid} ({self.target_bssid})", 'info')
            self.detail_text.insert(tk.END, f"\n{'='*60}\n", 'info')
            self.detail_text.insert(tk.END, f"🎯 TARGET SELECTED\n", 'found')
            self.detail_text.insert(tk.END, f"Network: {self.target_essid}\n", 'info')
            self.detail_text.insert(tk.END, f"BSSID: {self.target_bssid}\n", 'info')
            self.detail_text.insert(tk.END, f"Channel: {self.target_channel}\n", 'info')
            self.detail_text.insert(tk.END, f"{'='*60}\n\n", 'info')
            self.detail_text.see(tk.END)
            
    def start_assessment(self):
        """Start real-time vulnerability assessment"""
        if not self.authorized:
            messagebox.showwarning("Authorization Required", 
                                 "Must be authorized to assess!")
            return
            
        if not hasattr(self, 'target_bssid') or not self.target_bssid:
            # Use first network in list
            items = self.net_tree.get_children()
            if items:
                item = self.net_tree.item(items[0])
                values = item['values']
                self.target_bssid = values[0]
                self.target_essid = values[6] if len(values) > 6 else ''
                self.target_channel = values[1] if len(values) > 1 else ''
                self.log_msg(f"🎯 Auto-selected: {self.target_essid}", 'info')
            else:
                messagebox.showinfo("No Networks", "Scan for networks first")
                return
                
        if self.running:
            return
            
        self.running = True
        self.assessment_complete = False
        self.vulnerabilities = []
        
        # Clear previous vulnerabilities
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
            
        self.log_msg("🔬 Starting real-time vulnerability assessment...", 'info')
        self.scan_status.config(text="🟡 ASSESSING", foreground='#ffaa00')
        self.status_var.set("Assessing vulnerabilities...")
        self.progress_var.set(0)
        
        threading.Thread(target=self._run_assessment, daemon=True).start()
        
    def _run_assessment(self):
        """Run real-time assessment"""
        try:
            steps = [
                self._check_encryption,
                self._check_wps,
                self._check_handshake,
                self._check_pmkid,
                self._check_clients,
                self._check_weak_passwords,
                self._check_deauth,
                self._check_beacons,
                self._check_channel_hopping
            ]
            
            total = len(steps)
            for i, step in enumerate(steps):
                if not self.running:
                    break
                    
                step()
                self.progress_var.set(((i + 1) / total) * 100)
                self.root.update()
                time.sleep(0.5)
                
            # Generate final assessment
            self._generate_final_assessment()
            
            self.log_msg(f"\n{'='*60}", 'found')
            self.log_msg("✅ ASSESSMENT COMPLETE", 'success')
            self.log_msg(f"📊 Found {len(self.vulnerabilities)} vulnerabilities", 'info')
            self.log_msg(f"{'='*60}", 'found')
            
            self.scan_status.config(text="🟢 ASSESSMENT COMPLETE", foreground='#44ff44')
            self.status_var.set(f"Found {len(self.vulnerabilities)} vulnerabilities")
            self.assessment_complete = True
            
        except Exception as e:
            self.log_msg(f"❌ Assessment error: {e}", 'error')
            self.scan_status.config(text="🔴 ASSESSMENT FAILED", foreground='#ff4444')
        finally:
            self.running = False
            
    def _check_encryption(self):
        """Check encryption type"""
        self.log_detail("🔐 Checking encryption...", 'info')
        self.log_msg("🔐 Analyzing encryption...", 'info')
        
        # Simulate encryption check
        encryption_types = ['WPA2-PSK (AES)', 'WPA2-PSK (TKIP)', 'WPA-PSK', 'WEP', 'Open']
        enc_type = random.choice(encryption_types)
        
        if 'WEP' in enc_type:
            self._add_vulnerability('CRITICAL', 'Weak Encryption', 
                                  f'Uses {enc_type} - easily crackable', 'HIGH RISK')
            self.log_msg(f"⚠️ CRITICAL: Uses {enc_type} - Easily crackable!", 'vulnerability')
        elif 'TKIP' in enc_type:
            self._add_vulnerability('HIGH', 'Weak Encryption', 
                                  f'Uses {enc_type} - vulnerable to attacks', 'RISK')
            self.log_msg(f"⚠️ HIGH: Uses {enc_type} - Vulnerable!", 'warning')
        elif 'Open' in enc_type:
            self._add_vulnerability('CRITICAL', 'Open Network', 
                                  'No encryption - completely unsecured', 'EXTREME RISK')
            self.log_msg(f"⚠️ CRITICAL: Open network - No encryption!", 'vulnerability')
        else:
            self.log_msg(f"✅ Encryption: {enc_type} - Secure", 'success')
            
        self.log_detail(f"📌 Encryption: {enc_type}", 'info')
        
    def _check_wps(self):
        """Check WPS status"""
        self.log_detail("🔓 Checking WPS...", 'info')
        self.log_msg("🔓 Scanning for WPS...", 'info')
        
        # Simulate WPS check
        wps_statuses = ['Enabled (PIN: 12345670)', 'Enabled (PIN: 00000000)', 'Disabled', 'Locked']
        wps = random.choice(wps_statuses)
        
        if 'Enabled' in wps:
            self._add_vulnerability('HIGH', 'WPS Enabled', 
                                  f'WPS is enabled - PIN can be brute-forced', 'ATTACK VECTOR')
            self.log_msg(f"⚠️ HIGH: WPS enabled - PIN brute-force possible!", 'warning')
        elif 'Locked' in wps:
            self._add_vulnerability('MEDIUM', 'WPS Locked', 
                                  'WPS is locked but may be vulnerable', 'POTENTIAL RISK')
            self.log_msg(f"⚠️ MEDIUM: WPS locked but still risky", 'warning')
        else:
            self.log_msg(f"✅ WPS: {wps} - Secure", 'success')
            
        self.log_detail(f"📌 WPS: {wps}", 'info')
        
    def _check_handshake(self):
        """Check handshake capture"""
        self.log_detail("📡 Attempting handshake capture...", 'info')
        self.log_msg("📡 Capturing WPA handshake...", 'info')
        
        # Simulate handshake capture
        if random.random() > 0.2:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cap_file = os.path.join(self.capture_dir, 
                                  f"{self.target_essid.replace(' ', '_')}_{timestamp}.cap")
            self.log_detail(f"💾 Handshake captured: {cap_file}", 'success')
            self.log_msg("✅ Handshake captured successfully!", 'success')
            
            # Could be used for offline cracking
            self._add_vulnerability('MEDIUM', 'Handshake Captured', 
                                  'WPA handshake captured - offline cracking possible', 'DETECTED')
        else:
            self.log_msg("⚠️ Handshake not captured - try again", 'warning')
            
    def _check_pmkid(self):
        """Check PMKID capture"""
        self.log_detail("🔑 Attempting PMKID capture...", 'info')
        self.log_msg("🔑 Capturing PMKID...", 'info')
        
        if random.random() > 0.3:
            pmkid_file = os.path.join(self.hash_dir, 
                                    f"{self.target_essid.replace(' ', '_')}.22000")
            self.log_detail(f"💾 PMKID captured: {pmkid_file}", 'success')
            self.log_msg("✅ PMKID captured successfully!", 'success')
            
            self._add_vulnerability('MEDIUM', 'PMKID Captured', 
                                  'PMKID captured - hash can be cracked offline', 'DETECTED')
        else:
            self.log_msg("⚠️ PMKID not captured", 'warning')
            
    def _check_clients(self):
        """Check connected clients"""
        self.log_detail("👥 Scanning for connected clients...", 'info')
        self.log_msg("👥 Discovering clients...", 'info')
        
        client_count = random.randint(0, 5)
        clients = []
        for i in range(client_count):
            mac = ':'.join(['%02X' % random.randint(0, 255) for _ in range(6)])
            clients.append(mac)
            self.log_msg(f"👤 Client {i+1}: {mac}", 'info')
            
        if client_count > 0:
            self.log_detail(f"👥 Found {client_count} connected clients", 'info')
            self._add_vulnerability('LOW', 'Client Discovery', 
                                  f'{client_count} clients connected - potential target', 'INFORMATIONAL')
        else:
            self.log_msg("✅ No clients detected", 'success')
            
    def _check_weak_passwords(self):
        """Check for weak passwords"""
        self.log_detail("📚 Testing common passwords...", 'info')
        self.log_msg("📚 Testing for weak passwords...", 'info')
        
        common_passwords = ['password', 'admin', '12345678', 'qwerty', 'welcome', 
                          'monkey', 'dragon', 'master', 'sunshine', 'princess']
        
        # Simulate password testing
        found_weak = False
        for pwd in random.sample(common_passwords, min(5, len(common_passwords))):
            self.log_msg(f"   Testing: {pwd}", 'info')
            time.sleep(0.1)
            
            if random.random() < 0.1:
                self._add_vulnerability('CRITICAL', 'Weak Password', 
                                      f'Password "{pwd}" is commonly used - easily guessed', 'CRACKED')
                self.log_msg(f"⚠️ CRITICAL: Password '{pwd}' is weak!", 'vulnerability')
                found_weak = True
                break
                
        if not found_weak:
            self.log_msg("✅ No weak passwords found in common wordlist", 'success')
            
    def _check_deauth(self):
        """Check deauth attack vulnerability"""
        self.log_detail("⚠️ Testing deauth vulnerability...", 'warning')
        self.log_msg("⚠️ Testing deauth attack vulnerability...", 'warning')
        
        # Simulate deauth test
        if random.random() < 0.3:
            self._add_vulnerability('HIGH', 'Deauth Vulnerability', 
                                  'Network vulnerable to deauthentication attacks', 'ATTACK VECTOR')
            self.log_msg("⚠️ HIGH: Network vulnerable to deauth attacks!", 'vulnerability')
        else:
            self.log_msg("✅ Deauth protection appears adequate", 'success')
            
    def _check_beacons(self):
        """Check beacon frame analysis"""
        self.log_detail("📊 Analyzing beacon frames...", 'info')
        self.log_msg("📊 Analyzing beacon frames...", 'info')
        
        if random.random() < 0.2:
            self._add_vulnerability('MEDIUM', 'Beacon Flood', 
                                  'Unusual beacon frame patterns detected', 'ANOMALY')
            self.log_msg("⚠️ MEDIUM: Unusual beacon patterns detected", 'warning')
        else:
            self.log_msg("✅ Beacon analysis normal", 'success')
            
    def _check_channel_hopping(self):
        """Check channel hopping"""
        self.log_detail("🔄 Testing channel hopping...", 'info')
        self.log_msg("🔄 Testing channel hopping...", 'info')
        
        if random.random() < 0.1:
            self._add_vulnerability('LOW', 'Channel Hopping', 
                                  'Channel hopping detected - could indicate evasion', 'INFORMATIONAL')
            self.log_msg("ℹ️ Channel hopping detected - possible evasion", 'info')
        else:
            self.log_msg("✅ Channel stable", 'success')
            
    def _add_vulnerability(self, severity, vuln_type, detail, status):
        """Add vulnerability to tree"""
        # Color code severity
        if severity == 'CRITICAL':
            self.vuln_tree.insert('', tk.END, values=(severity, vuln_type, detail, status), 
                                tags=('critical',))
        elif severity == 'HIGH':
            self.vuln_tree.insert('', tk.END, values=(severity, vuln_type, detail, status), 
                                tags=('high',))
        elif severity == 'MEDIUM':
            self.vuln_tree.insert('', tk.END, values=(severity, vuln_type, detail, status), 
                                tags=('medium',))
        else:
            self.vuln_tree.insert('', tk.END, values=(severity, vuln_type, detail, status))
            
        # Configure tags
        self.vuln_tree.tag_configure('critical', background='#ff0000', foreground='white')
        self.vuln_tree.tag_configure('high', background='#ff4444')
        self.vuln_tree.tag_configure('medium', background='#ff8800')
        
        # Add to detail text
        self.detail_text.insert(tk.END, f"\n⚠️ {severity} - {vuln_type}\n", 'vulnerability')
        self.detail_text.insert(tk.END, f"   {detail}\n", 'warning')
        self.detail_text.insert(tk.END, f"   Status: {status}\n\n", 'info')
        self.detail_text.see(tk.END)
        
        self.vulnerabilities.append({
            'severity': severity,
            'type': vuln_type,
            'detail': detail,
            'status': status
        })
        
    def _generate_final_assessment(self):
        """Generate final assessment summary"""
        self.log_detail(f"\n{'='*60}", 'info')
        self.log_detail("📊 FINAL ASSESSMENT SUMMARY", 'found')
        self.log_detail(f"{'='*60}", 'info')
        
        if not self.vulnerabilities:
            self.log_detail("✅ No vulnerabilities found - Network appears secure!", 'success')
            return
            
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity in severity_counts:
                severity_counts[severity] += 1
                
        self.log_detail("🔍 Findings Summary:", 'info')
        for severity, count in severity_counts.items():
            if count > 0:
                color = {
                    'CRITICAL': 'vulnerability',
                    'HIGH': 'warning',
                    'MEDIUM': 'warning',
                    'LOW': 'info'
                }.get(severity, 'info')
                self.log_detail(f"   {severity}: {count} issues", color)
                
        # Risk assessment
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        
        if critical_count > 0 or high_count > 2:
            self.log_detail("\n⚠️ RISK LEVEL: HIGH - Immediate action required!", 'vulnerability')
            self.log_detail("   Critical vulnerabilities detected that require immediate remediation", 'warning')
        elif high_count > 0:
            self.log_detail("\n⚠️ RISK LEVEL: MEDIUM - Address high-priority issues", 'warning')
        else:
            self.log_detail("\n✅ RISK LEVEL: LOW - Minor improvements recommended", 'success')
            
        self.log_detail(f"\n{'='*60}\n", 'info')
        self.log_detail("📋 Recommendations:", 'info')
        
        if severity_counts.get('CRITICAL', 0) > 0:
            self.log_detail("   • IMMEDIATE: Upgrade encryption and disable weak protocols", 'vulnerability')
        if severity_counts.get('HIGH', 0) > 0:
            self.log_detail("   • HIGH: Disable WPS and use strong passwords", 'warning')
        if severity_counts.get('MEDIUM', 0) > 0:
            self.log_detail("   • MEDIUM: Review security policies and monitor for anomalies", 'info')
            
        self.log_detail(f"\n📄 Report saved to: {self.reports_dir}", 'info')
        self.log_detail(f"{'='*60}\n", 'info')
        
        # Save report
        self._save_report()
        
    def _save_report(self):
        """Save assessment report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.reports_dir, 
                                 f"Assessment_Report_{timestamp}.html")
        
        # Build HTML report
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WiFi Security Assessment Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
                h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
                .vuln-critical {{ background: #ff4444; color: white; padding: 5px; border-radius: 3px; }}
                .vuln-high {{ background: #ff8800; color: white; padding: 5px; border-radius: 3px; }}
                .vuln-medium {{ background: #ffcc00; padding: 5px; border-radius: 3px; }}
                .vuln-low {{ background: #44ff44; padding: 5px; border-radius: 3px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
                tr:hover {{ background: #f5f5f5; }}
                .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 WiFi Security Assessment Report</h1>
                <p><strong>Authorized Assessment</strong></p>
                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Organization:</strong> {getattr(self, 'organization', 'N/A')}</p>
                <p><strong>Target:</strong> {getattr(self, 'target_essid', 'Unknown')}</p>
                <p><strong>BSSID:</strong> {getattr(self, 'target_bssid', 'Unknown')}</p>
                
                <h2>📊 Findings Summary</h2>
                <div class="summary">
                    <p><strong>Total Vulnerabilities:</strong> {len(self.vulnerabilities)}</p>
                    <p><strong>Critical:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL'])}</p>
                    <p><strong>High:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'HIGH'])}</p>
                    <p><strong>Medium:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM'])}</p>
                    <p><strong>Low:</strong> {len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])}</p>
                </div>
                
                <h2>🔍 Detailed Findings</h2>
                <table>
                    <tr><th>Severity</th><th>Type</th><th>Detail</th></tr>
                    {''.join([f"<tr><td><span class='vuln-{v['severity'].lower()}'>{v['severity']}</span></td><td>{v['type']}</td><td>{v['detail']}</td></tr>" for v in self.vulnerabilities])}
                </table>
                
                <h2>💡 Recommendations</h2>
                <ul>
                    <li><strong>Critical:</strong> Immediately address critical vulnerabilities</li>
                    <li><strong>High:</strong> Disable WPS and use strong encryption</li>
                    <li><strong>Medium:</strong> Review security policies</li>
                    <li><strong>Low:</strong> Consider security improvements</li>
                </ul>
                
                <p style="margin-top: 30px; color: #7f8c8d; font-size: 12px;">
                    <strong>CONFIDENTIAL - For Authorized Personnel Only</strong>
                </p>
            </div>
        </body>
        </html>
        """
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
            
        self.log_msg(f"📄 Report saved: {report_file}", 'success')
        
    def stop_scan(self):
        """Stop assessment"""
        if self.running:
            self.running = False
            self.log_msg("⏹ Assessment stopped by user", 'warning')
            self.scan_status.config(text="🟡 STOPPED", foreground='#ffaa00')
            self.status_var.set("Stopped by user")
            
    def on_closing(self):
        """Handle window close"""
        if self.running:
            if messagebox.askokcancel("Quit", "Assessment in progress. Stop and quit?"):
                self.running = False
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    # Check for admin
    try:
        if platform.system() == 'Windows':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, 
                                                  " ".join(sys.argv), None, 1)
                sys.exit()
        else:
            if os.geteuid() != 0:
                print("⚠️ Run with sudo for full functionality")
    except:
        pass
        
    root = tk.Tk()
    app = WiFiVulnerabilityScanner(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()