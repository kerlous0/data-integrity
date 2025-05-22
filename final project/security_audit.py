import subprocess
import sys
import time
import json
import os
import shutil
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import threading
import signal

# Suppress SSL warnings for demo purposes
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SecurityAudit:
    def __init__(self):
        self.capture_processes = []
        self.results = {
            'http_vulnerabilities': [],
            'https_protections': [],
            'mitm_simulation_results': {},
            'timestamps': {}
        }
        
    def check_dependencies(self):
        """Check if required tools are installed."""
        required_tools = ['tshark', 'curl']
        missing_tools = []
        
        for tool in required_tools:
            if not shutil.which(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            print("Error: Missing required tools!")
            for tool in missing_tools:
                if tool == 'tshark':
                    print(f"- {tool}: Install Wireshark from https://www.wireshark.org/download.html")
                    print("  Make sure to install TShark and add to PATH")
                elif tool == 'curl':
                    print(f"- {tool}: Install curl from https://curl.se/download.html")
            return False
        return True

    def get_network_interfaces(self):
        """Get available network interfaces."""
        try:
            result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, timeout=10)
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    interfaces.append(line.strip())
            return interfaces
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print("Warning: Could not enumerate network interfaces")
            return ["1. Any (Pseudo-device that captures on all interfaces)"]

    def start_capture(self, output_file, capture_filter="host 127.0.0.1", interface="1"):
        """Start network capture."""
        os.makedirs('captures', exist_ok=True)
        
        print(f"Starting capture: {output_file}")
        try:
            proc = subprocess.Popen([
                "tshark",
                "-i", interface,
                "-w", output_file,
                "-f", capture_filter,
                "-q"  # Quiet mode
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.capture_processes.append(proc)
            return proc
        except Exception as e:
            print(f"Error starting capture: {e}")
            return None

    def stop_capture(self, process):
        """Stop network capture."""
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            print("Capture stopped.")

    def analyze_http_traffic(self, capture_file):
        """Analyze HTTP traffic to demonstrate vulnerabilities."""
        print(f"\n=== Analyzing HTTP Traffic: {capture_file} ===")
        
        if not os.path.exists(capture_file):
            print(f"Capture file not found: {capture_file}")
            return
        
        vulnerabilities = []
        
        try:
            # Extract HTTP requests and responses
            print("Extracting HTTP requests...")
            result = subprocess.run([
                "tshark", "-r", capture_file,
                "-Y", "http.request",
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-e", "http.request.full_uri"
            ], capture_output=True, text=True, timeout=30)
            
            if result.stdout.strip():
                print("🚨 SECURITY VULNERABILITY DETECTED:")
                print("HTTP requests are transmitted in PLAIN TEXT!")
                print("\nIntercepted HTTP Requests:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        fields = line.split('\t')
                        if len(fields) >= 6:
                            timestamp, src, dst, method, uri, full_uri = fields[:6]
                            print(f"  Time: {timestamp}")
                            print(f"  Source: {src} → Destination: {dst}")
                            print(f"  Method: {method} {uri}")
                            print(f"  Full URL: {full_uri}")
                            print("  " + "="*50)
                            
                            vulnerabilities.append({
                                'type': 'plaintext_http',
                                'timestamp': timestamp,
                                'method': method,
                                'uri': uri,
                                'risk': 'HIGH - Request visible to attackers'
                            })
            
            # Extract HTTP form data and cookies
            print("\nExtracting sensitive HTTP data...")
            result = subprocess.run([
                "tshark", "-r", capture_file,
                "-Y", "http.request.method == \"POST\"",
                "-T", "fields",
                "-e", "http.file_data",
                "-e", "http.cookie"
            ], capture_output=True, text=True, timeout=30)
            
            if result.stdout.strip():
                print("🚨 CRITICAL: POST data and cookies intercepted!")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        fields = line.split('\t')
                        if len(fields) >= 1 and fields[0]:
                            print(f"  POST Data: {fields[0][:100]}...")
                            vulnerabilities.append({
                                'type': 'plaintext_post_data',
                                'data_preview': fields[0][:100],
                                'risk': 'CRITICAL - Sensitive data exposed'
                            })
                        if len(fields) >= 2 and fields[1]:
                            print(f"  Cookies: {fields[1]}")
                            vulnerabilities.append({
                                'type': 'plaintext_cookies',
                                'cookies': fields[1],
                                'risk': 'HIGH - Session data exposed'
                            })
            
            self.results['http_vulnerabilities'] = vulnerabilities
            
        except subprocess.TimeoutExpired:
            print("Analysis timed out")
        except Exception as e:
            print(f"Error analyzing HTTP traffic: {e}")

    def analyze_https_traffic(self, capture_file):
        """Analyze HTTPS traffic to demonstrate protection."""
        print(f"\n=== Analyzing HTTPS Traffic: {capture_file} ===")
        
        if not os.path.exists(capture_file):
            print(f"Capture file not found: {capture_file}")
            return
        
        protections = []
        
        try:
            # Show TLS handshake
            print("Analyzing TLS handshake...")
            result = subprocess.run([
                "tshark", "-r", capture_file,
                "-Y", "tls.handshake.type",
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tls.handshake.type",
                "-e", "tls.handshake.version"
            ], capture_output=True, text=True, timeout=30)
            
            if result.stdout.strip():
                print("✅ SECURE: TLS encryption established!")
                print("\nTLS Handshake Details:")
                handshake_types = {
                    '1': 'Client Hello',
                    '2': 'Server Hello', 
                    '11': 'Certificate',
                    '12': 'Server Key Exchange',
                    '14': 'Server Hello Done',
                    '16': 'Client Key Exchange',
                    '20': 'Finished'
                }
                
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        fields = line.split('\t')
                        if len(fields) >= 4:
                            timestamp, src, dst, handshake_type = fields[:4]
                            handshake_name = handshake_types.get(handshake_type, f'Type {handshake_type}')
                            print(f"  {timestamp}: {src} → {dst} - {handshake_name}")
                            
                protections.append({
                    'type': 'tls_handshake',
                    'timestamp': timestamp,
                    'protection': 'Encrypted connection established'
                })
            
            # Show encrypted application data
            print("\nAnalyzing encrypted application data...")
            result = subprocess.run([
                "tshark", "-r", capture_file,
                "-Y", "tls.app_data",
                "-T", "fields",
                "-e", "frame.time",
                "-e", "frame.len",
                "-e", "tls.app_data"
            ], capture_output=True, text=True, timeout=30)
            
            if result.stdout.strip():
                print("✅ SECURE: Application data is encrypted!")
                print("\nEncrypted Data Packets:")
                for line in result.stdout.strip().split('\n')[:5]:  # Show first 5 packets
                    if line.strip():
                        fields = line.split('\t')
                        if len(fields) >= 2:
                            timestamp, frame_len = fields[:2]
                            print(f"  {timestamp}: {frame_len} bytes of encrypted data")
                            print(f"    Content: [ENCRYPTED - Cannot be read by attackers]")
                            
                protections.append({
                    'type': 'encrypted_data',
                    'protection': 'Application data encrypted and unreadable'
                })
            
            self.results['https_protections'] = protections
            
        except subprocess.TimeoutExpired:
            print("Analysis timed out")
        except Exception as e:
            print(f"Error analyzing HTTPS traffic: {e}")

    def simulate_mitm_attack(self):
        """Simulate MITM attack scenarios."""
        print("\n" + "="*60)
        print("🔥 SIMULATING MAN-IN-THE-MIDDLE (MITM) ATTACK")
        print("="*60)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Test HTTP vulnerability
        print("\n1. Testing HTTP Vulnerability (Insecure Communication)")
        print("-" * 50)
        
        http_capture = f"captures/mitm_http_attack_{timestamp}.pcap"
        capture_proc = self.start_capture(http_capture, "host 127.0.0.1 and port 5000")
        
        if capture_proc:
            time.sleep(2)  # Allow capture to start
            
            print("Simulating user login over HTTP...")
            try:
                # Simulate form submission
                response = requests.post(
                    "http://127.0.0.1:5000/auth/login",
                    data={
                        'email': 'admin@gmail.com',
                        'password': 'admin123A@',
                        'remember_me': False
                    },
                    timeout=10,
                    allow_redirects=False
                )
                print(f"HTTP request sent (Status: {response.status_code})")
            except requests.exceptions.RequestException as e:
                print(f"Request failed (this is normal for demo): {e}")
            
            time.sleep(3)  # Allow packets to be captured
            self.stop_capture(capture_proc)
            
            # Analyze the vulnerability
            self.analyze_http_traffic(http_capture)
        
        # Test HTTPS protection
        print("\n2. Testing HTTPS Protection (Secure Communication)")
        print("-" * 50)
        
        https_capture = f"captures/mitm_https_protection_{timestamp}.pcap"
        capture_proc = self.start_capture(https_capture, "host 127.0.0.1 and port 5443")
        
        if capture_proc:
            time.sleep(2)  # Allow capture to start
            
            print("Simulating user login over HTTPS...")
            try:
                # Simulate secure form submission
                response = requests.post(
                    "https://127.0.0.1:5443/auth/login",
                    data={
                        'email': 'admin@gmail.com',
                        'password': 'admin123A@',
                        'remember_me': False
                    },
                    verify=False,  # Allow self-signed cert for demo
                    timeout=10,
                    allow_redirects=False
                )
                print(f"HTTPS request sent (Status: {response.status_code})")
            except requests.exceptions.RequestException as e:
                print(f"Request failed (this is normal for demo): {e}")
            
            time.sleep(3)  # Allow packets to be captured
            self.stop_capture(capture_proc)
            
            # Analyze the protection
            self.analyze_https_traffic(https_capture)

    def generate_summary_report(self):
        """Generate a comprehensive security audit report."""
        print("\n" + "="*60)
        print("📊 SECURITY AUDIT SUMMARY REPORT")
        print("="*60)
        
        print(f"\nAudit completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n🚨 HTTP VULNERABILITIES FOUND:")
        print("-" * 30)
        if self.results['http_vulnerabilities']:
            for vuln in self.results['http_vulnerabilities']:
                print(f"• {vuln['type'].upper()}: {vuln['risk']}")
        else:
            print("• No HTTP traffic captured (application may not be running)")
            
        print("\n✅ HTTPS PROTECTIONS VERIFIED:")
        print("-" * 30)
        if self.results['https_protections']:
            for protection in self.results['https_protections']:
                print(f"• {protection['type'].upper()}: {protection['protection']}")
        else:
            print("• No HTTPS traffic captured (application may not be running)")
        
        print(f"\n📁 Capture files saved in: {os.path.abspath('captures')}")
        
        # Security recommendations
        print("\n🔒 SECURITY RECOMMENDATIONS:")
        print("-" * 30)
        print("1. ✅ Always use HTTPS in production")
        print("2. ✅ Implement HSTS headers")
        print("3. ✅ Use secure session cookies")
        print("4. ✅ Enable certificate pinning")
        print("5. ✅ Implement proper input validation")
        print("6. ✅ Use strong authentication (2FA)")
        
        # Save report to file
        report_file = f"captures/security_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'audit_timestamp': datetime.now().isoformat(),
                'vulnerabilities': self.results['http_vulnerabilities'],
                'protections': self.results['https_protections'],
                'recommendations': [
                    "Always use HTTPS in production",
                    "Implement HSTS headers",
                    "Use secure session cookies",
                    "Enable certificate pinning",
                    "Implement proper input validation",
                    "Use strong authentication (2FA)"
                ]
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")

    def cleanup(self):
        """Clean up any running processes."""
        for proc in self.capture_processes:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def run_audit(self):
        """Run the complete security audit."""
        print("🔍 SECURITY AUDIT & MITM SIMULATION")
        print("="*50)
        print("This tool demonstrates:")
        print("• How HTTP traffic can be intercepted (MITM vulnerability)")
        print("• How HTTPS protects against traffic interception")
        print("• Real packet capture analysis using Wireshark")
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Show available interfaces
        interfaces = self.get_network_interfaces()
        print(f"\nAvailable network interfaces:")
        for interface in interfaces[:5]:  # Show first 5
            print(f"  {interface}")
        
        try:
            # Run MITM simulation
            self.simulate_mitm_attack()
            
            # Generate report
            self.generate_summary_report()
            
            return True
            
        except KeyboardInterrupt:
            print("\n\nAudit cancelled by user.")
            return False
        except Exception as e:
            print(f"\nError during audit: {e}")
            return False
        finally:
            self.cleanup()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print('\n\nReceived interrupt signal. Cleaning up...')
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    audit = SecurityAudit()
    try:
        success = audit.run_audit()
        if success:
            print("\n✅ Security audit completed successfully!")
            print("Check the 'captures' directory for detailed packet analysis.")
        else:
            print("\n❌ Security audit failed or was cancelled.")
            sys.exit(1)
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)
    finally:
        audit.cleanup()