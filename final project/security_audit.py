import subprocess
import sys
import time
from datetime import datetime
import os
import shutil

def check_dependencies():
    """Check if required tools are installed."""
    if not shutil.which('tshark'):
        print("Error: tshark not found!")
        print("Please install Wireshark from https://www.wireshark.org/download.html")
        print("Make sure to:")
        print("1. Install WinPcap/Npcap when prompted")
        print("2. Check the box to install TShark")
        print("3. Add Wireshark to your system PATH")
        print("4. Restart your terminal after installation")
        return False
    return True

def start_wireshark_capture(output_file, interface=r"\Device\NPF_{2BEA668F-C02B-4656-BF67-D4756143E5E0}"):
    """Start Wireshark capture in the background."""
    # Ensure captures directory exists
    os.makedirs('captures', exist_ok=True)
    
    print(f"Starting Wireshark capture on {interface}...")
    try:
        return subprocess.Popen([
            "tshark",
            "-i", interface,
            "-w", output_file,
            "host", "127.0.0.1",
            "and", "(port 5000 or port 5443)"  # Capture both HTTP and HTTPS
        ])
    except subprocess.CalledProcessError as e:
        print(f"Error starting capture: {e}")
        return None
    except FileNotFoundError:
        print("Error: tshark command not found. Please ensure Wireshark is properly installed.")
        return None

def analyze_capture(capture_file):
    """Analyze the captured traffic."""
    if not os.path.exists(capture_file):
        print(f"Error: Capture file {capture_file} not found!")
        return
        
    print("\nAnalyzing captured traffic...")
    try:
        subprocess.run([
            "tshark",
            "-r", capture_file,
            "-Y", "http || ssl || tls",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ssl.handshake.type",
            "-e", "http.request.method",
            "-e", "http.request.uri"
        ])
    except subprocess.CalledProcessError as e:
        print(f"Error analyzing capture: {e}")
    except FileNotFoundError:
        print("Error: tshark command not found. Please ensure Wireshark is properly installed.")

def run_security_audit():
    """Run the security audit demonstration."""
    # Check dependencies first
    if not check_dependencies():
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    http_capture = f"captures/http_traffic_{timestamp}.pcap"
    https_capture = f"captures/https_traffic_{timestamp}.pcap"
    
    # Test 1: Capture HTTP traffic
    print("\n=== Testing HTTP Traffic (Insecure) ===")
    capture_proc = start_wireshark_capture(http_capture)
    if not capture_proc:
        return
        
    time.sleep(2)  # Wait for capture to start
    
    print("Making HTTP request...")
    try:
        subprocess.run(["curl", "http://127.0.0.1:5000"], capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Error making HTTP request: {e}")
    
    time.sleep(2)  # Wait for packets to be captured
    capture_proc.terminate()
    
    # Test 2: Capture HTTPS traffic
    print("\n=== Testing HTTPS Traffic (Secure) ===")
    capture_proc = start_wireshark_capture(https_capture)
    if not capture_proc:
        return
        
    time.sleep(2)  # Wait for capture to start
    
    print("Making HTTPS request...")
    try:
        subprocess.run([
            "curl", 
            "--insecure",  # Allow self-signed cert
            "https://127.0.0.1:5443"
        ], capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Error making HTTPS request: {e}")
    
    time.sleep(2)  # Wait for packets to be captured
    capture_proc.terminate()
    
    # Analyze captures
    print("\n=== HTTP Traffic Analysis ===")
    analyze_capture(http_capture)
    
    print("\n=== HTTPS Traffic Analysis ===")
    analyze_capture(https_capture)
    
    print("\nSecurity audit complete! Check the captures/ directory for detailed packet captures.")

if __name__ == "__main__":
    try:
        run_security_audit()
    except KeyboardInterrupt:
        print("\nAudit cancelled by user.")
    except Exception as e:
        print(f"\nError during audit: {e}")
        sys.exit(1)