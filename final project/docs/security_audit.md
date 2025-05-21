# Security Audit Documentation

This document explains how to perform and understand the security audit simulation for the SecureDocs application.

## Prerequisites

1. Install Wireshark and tshark:

   ```bash
   # Windows (using chocolatey)
   choco install wireshark

   # Linux
   sudo apt-get install wireshark tshark
   ```

2. SSL Certificates:
   - Ensure SSL certificates are generated in the `ssl/` directory
   - Use the provided OpenSSL commands or your own certificates

## Running the Security Audit

1. Start both HTTP and HTTPS servers:

   ```bash
   # Terminal 1 - HTTP server (port 5000)
   flask run

   # Terminal 2 - HTTPS server (port 5443)
   python run_https.py
   ```

2. In a new terminal, run the security audit:
   ```bash
   python security_audit.py
   ```

## Understanding the Results

### HTTP Traffic (Insecure)

- Plain text data visible in packet captures
- No encryption of sensitive information
- Vulnerable to:
  - Man-in-the-Middle (MITM) attacks
  - Packet sniffing
  - Data manipulation

### HTTPS Traffic (Secure)

- Encrypted data in packet captures
- SSL/TLS handshake visible but content encrypted
- Protected against:
  - MITM attacks (with valid certificates)
  - Packet sniffing
  - Data manipulation

## Analyzing Wireshark Captures

The script generates two capture files in the `captures/` directory:

1. `http_traffic_[timestamp].pcap` - Insecure HTTP traffic (port 5000)
2. `https_traffic_[timestamp].pcap` - Secure HTTPS traffic (port 5443)

To analyze manually:

1. Open captures in Wireshark
2. Look for:
   - HTTP requests/responses (plain text in HTTP)
   - TLS handshake packets (in HTTPS)
   - Encrypted application data (in HTTPS)

## Security Recommendations

1. Always use HTTPS in production
2. Keep SSL certificates up to date
3. Use strong cipher suites
4. Enable HTTP Strict Transport Security (HSTS)
5. Regular security audits and penetration testing

## Screenshots

Include screenshots of:

1. Wireshark capture of HTTP traffic showing exposed data
2. Wireshark capture of HTTPS traffic showing encrypted data
3. SSL certificate details
4. Successful HTTPS connection in browser

## Note on Port Usage

- HTTP server runs on port 5000 (development)
- HTTPS server runs on port 5443 (development)
- In production, you should use standard ports (80 for HTTP, 443 for HTTPS) with proper permissions
