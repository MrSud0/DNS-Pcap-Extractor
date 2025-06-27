# Advanced DNS Exfiltration Analyzer

A comprehensive Python tool for analyzing DNS traffic and detecting data exfiltration in packet captures. This tool can identify, decode, and reassemble data that has been exfiltrated through DNS queries using various encoding schemes.

## 🚀 Features

- **Multi-Encoding Support**: Hex, Base64, Base32, ASCII codes, Binary encoding detection
- **Automatic Detection**: Smart pattern recognition for encoded data in DNS queries
- **Data Reassembly**: Reconstruct exfiltrated files from fragmented DNS queries
- **Pattern Analysis**: Identify suspicious DNS query patterns and behaviors
- **Flexible Filtering**: Domain-based filtering and query length thresholds
- **Comprehensive Reporting**: JSON exports, binary extraction, and human-readable summaries
- **Professional CLI**: Full command-line interface with extensive options

## 📦 Installation

### Requirements
- Python 3.6+
- Scapy library for packet analysis

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/dns-exfiltration-analyzer.git
cd dns-exfiltration-analyzer

# Install dependencies
pip install scapy

# Make executable (optional)
chmod +x dns_analyzer.py

# Test installation
python dns_analyzer.py --help
```

### Dependencies
```bash
# Core requirement
pip install scapy

# Optional: For enhanced packet analysis
pip install pyshark tshark
```

## 💻 Usage

### Basic Examples

#### Analyze a PCAP file
```bash
# Basic analysis with default settings
python dns_analyzer.py capture.pcap

# Specify input and output explicitly
python dns_analyzer.py -i network_traffic.pcap -o analysis_results
```

#### Target specific domains
```bash
# Focus on suspicious domain
python dns_analyzer.py -i capture.pcap --domain evil.com

# Analyze corporate data exfiltration
python dns_analyzer.py -i traffic.pcap --domain company-data.attacker.com
```

#### Force specific encoding types
```bash
# Look specifically for hex-encoded data
python dns_analyzer.py -i capture.pcap --encoding hex

# Focus on base64 exfiltration
python dns_analyzer.py -i capture.pcap --encoding base64

# Auto-detect all encoding types (default)
python dns_analyzer.py -i capture.pcap --encoding auto
```

### Advanced Usage

#### Custom filtering and analysis
```bash
# Filter short queries (reduce noise)
python dns_analyzer.py -i capture.pcap --min-length 10

# Use sequence-based reassembly for ordered data
python dns_analyzer.py -i capture.pcap --reassemble sequence

# Verbose output for debugging
python dns_analyzer.py -i capture.pcap -v
```

#### Comprehensive analysis pipeline
```bash
# Complete analysis with all options
python dns_analyzer.py \
    -i suspicious_traffic.pcap \
    -o detailed_analysis \
    --domain attacker.com \
    --encoding auto \
    --min-length 8 \
    --reassemble timestamp \
    --verbose
```

### Command-Line Options

```
usage: dns_analyzer.py [-h] [-i INPUT] [-o OUTPUT] 
                      [--encoding {auto,hex,base64,base32,ascii,binary}]
                      [--domain DOMAIN] [--min-length MIN_LENGTH]
                      [--reassemble {timestamp,sequence,none}] [-v]
                      [pcap_file]

Advanced DNS Exfiltration Analyzer

positional arguments:
  pcap_file             PCAP file to analyze (default: capture.pcap)

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input PCAP file
  -o OUTPUT, --output OUTPUT
                        Output directory (default: dns_analysis)
  --encoding {auto,hex,base64,base32,ascii,binary}
                        Encoding type to analyze (default: auto)
  --domain DOMAIN       Filter DNS queries by domain
  --min-length MIN_LENGTH
                        Minimum query length to analyze (default: 4)
  --reassemble {timestamp,sequence,none}
                        Data reassembly method (default: timestamp)
  -v, --verbose         Enable verbose output
```

## 📊 Example Output

### Console Output
```
[*] Starting DNS exfiltration analysis...
[*] Loading PCAP file: suspicious_traffic.pcap
[*] Processing 15847 packets...
[+] Found 342 DNS requests (89 unique)
[*] Analyzing query patterns...
[+] Pattern analysis saved to: dns_analysis/pattern_analysis.json
[*] Extracting encoded data (encoding: auto)...
[+] Extracted 23 encoded data segments
[*] Reassembling data using method: timestamp
[+] Reassembled 15 hex segments (2048 bytes)
[+] Reassembled 8 base64 segments (1024 bytes)
[*] Saving analysis results...
[+] Saved binary data: dns_analysis/reassembled_hex.bin
[+] Saved binary data: dns_analysis/reassembled_base64.bin
[+] All results saved to: dns_analysis

============================================================
DNS EXFILTRATION ANALYSIS REPORT
============================================================

File: suspicious_traffic.pcap
Analysis Time: 2024-01-15 14:30:25

Statistics:
  Total Packets: 15847
  DNS Requests: 342
  Unique Queries: 89
  Extracted Segments: 23

Encoding Distribution:
  hex: 15 segments
  base64: 8 segments

Reassembled Data:
  HEX:
    Segments: 15
    Size: 2048 bytes
    Content: Secret document content...
  BASE64:
    Segments: 8
    Size: 1024 bytes
    Preview: {"password":"admin123","users":["alice","bob"]...
```

### Output Directory Structure
```
dns_analysis/
├── dns_requests.json          # Complete DNS request data with timestamps
├── pattern_analysis.json      # Suspicious pattern detection results
├── extracted_data.json        # Individual decoded segments
├── reassembled_data.json      # Reassembled data by encoding type
├── analysis_summary.txt       # Human-readable analysis report
├── reassembled_hex.bin        # Reconstructed hex-encoded data
├── reassembled_base64.bin     # Reconstructed base64-encoded data
└── ...                        # Additional binary files as found
```

## 🔍 Supported Encoding Methods

| Encoding | Description | Example Pattern | Detection Method |
|----------|-------------|-----------------|------------------|
| **Hex** | Hexadecimal encoding | `48656c6c6f.evil.com` | Even length, [0-9a-fA-F] only |
| **Base64** | Base64 encoding | `SGVsbG8.evil.com` | Length divisible by 4, [A-Za-z0-9+/] |
| **Base32** | Base32 encoding | `JBSWY3DP.evil.com` | Length divisible by 8, [A-Z2-7] |
| **ASCII** | ASCII character codes | `72101108108111.evil.com` | Numeric codes for printable chars |
| **Binary** | Binary encoding | `0100100001100101.evil.com` | Binary digits only, length divisible by 8 |

## 🎯 Use Cases

### CTF Challenges
- **DNS Exfiltration**: Extract hidden flags from DNS traffic captures
- **Multi-Stage Puzzles**: Reassemble fragmented data across multiple queries
- **Encoding Challenges**: Identify and decode various encoding schemes
- **Traffic Analysis**: Analyze suspicious DNS patterns for clues

### Digital Forensics
- **Incident Response**: Detect data exfiltration in network captures
- **Malware Analysis**: Analyze C&C communication through DNS
- **Data Breach Investigation**: Reconstruct stolen data from DNS logs
- **Threat Hunting**: Identify suspicious DNS query patterns

### Security Research
- **Exfiltration Techniques**: Study DNS-based data exfiltration methods
- **Pattern Analysis**: Research encoding patterns used by malware
- **Defense Development**: Test DNS security monitoring tools
- **Network Analysis**: Understand DNS-based covert channels

### Penetration Testing
- **Red Team Exercises**: Analyze your own DNS exfiltration attempts
- **Blue Team Training**: Practice detecting DNS-based attacks
- **Tool Validation**: Test DNS monitoring and detection capabilities
- **Technique Documentation**: Document exfiltration methods and countermeasures

## 🔧 Technical Details

### Data Extraction Process
1. **PCAP Parsing**: Extract DNS queries using Scapy
2. **Pattern Recognition**: Identify encoded data in query names
3. **Encoding Detection**: Test multiple encoding schemes
4. **Data Validation**: Verify decoded data integrity
5. **Reassembly**: Reconstruct original data from fragments
6. **Output Generation**: Create comprehensive analysis reports

### Reassembly Methods
- **Timestamp-based**: Orders data by packet capture time
- **Sequence-based**: Extracts sequence numbers from DNS queries
- **Manual**: Preserves original order without sorting

### Pattern Detection
The tool identifies suspicious patterns including:
- Long hexadecimal strings in subdomains
- Base64-encoded data with proper padding
- Numeric sequences that could be ASCII codes
- Binary data patterns
- Unusual query lengths and frequencies

### Security Considerations
- **Safe Decoding**: Handles malformed encoding gracefully
- **Memory Management**: Efficient processing of large PCAP files
- **Error Isolation**: Continues analysis despite individual decode failures
- **Path Validation**: Secure output file handling

## 🚨 Troubleshooting

### Common Issues

**"Scapy not available" error**
```bash
# Install Scapy
pip install scapy

# On some systems, you may need:
pip3 install scapy
sudo apt-get install python3-scapy  # Ubuntu/Debian
```

**"No DNS data found" warning**
- Verify the PCAP contains DNS traffic: `tcpdump -r capture.pcap port 53`
- Check if DNS queries are encrypted (DNS over HTTPS/TLS)
- Ensure the PCAP file is not corrupted: `capinfos capture.pcap`

**"Permission denied" errors**
- Check file permissions: `ls -la capture.pcap`
- Ensure output directory is writable
- Run with appropriate user permissions

**Memory issues with large PCAP files**
- Use filtering options to reduce data: `--domain`, `--min-length`
- Split large PCAP files: `editcap -c 10000 large.pcap split.pcap`
- Increase system memory or use a more powerful machine

### Debug Tips

1. **Verify PCAP contents**:
   ```bash
   tcpdump -r capture.pcap -c 10 port 53
   ```

2. **Test with known data**:
   ```bash
   # Create test DNS query with known encoded data
   echo "test data" | xxd -p | tr -d '\n'
   # Result: 7465737420646174610a
   ```

3. **Use verbose mode**:
   ```bash
   python dns_analyzer.py -i capture.pcap -v
   ```

4. **Check specific domains**:
   ```bash
   python dns_analyzer.py -i capture.pcap --domain suspicious.com -v
   ```

## 🤝 Contributing

Contributions are welcome! Here are ways you can help:

### Adding Features
- **New Encoding Methods**: Implement additional encoding schemes
- **Advanced Reassembly**: Improve data reconstruction algorithms
- **Pattern Detection**: Add new suspicious pattern recognition
- **Export Formats**: Support additional output formats

### Improvements
- **Performance**: Optimize for larger PCAP files
- **Accuracy**: Improve encoding detection accuracy
- **Usability**: Enhance CLI interface and error messages
- **Documentation**: Improve examples and use cases

### Bug Fixes
- **Edge Cases**: Handle unusual DNS query formats
- **Error Handling**: Improve graceful failure modes
- **Compatibility**: Ensure cross-platform functionality
- **Memory Usage**: Optimize resource consumption

### Development Setup
```bash
git clone https://github.com/yourusername/dns-exfiltration-analyzer.git
cd dns-exfiltration-analyzer

# Install development dependencies
pip install scapy pytest black flake8

# Run tests
pytest tests/

# Format code
black dns_analyzer.py

# Lint code
flake8 dns_analyzer.py
```

### Testing
```bash
# Unit tests
python -m pytest tests/test_decoding.py

# Integration tests
python -m pytest tests/test_analysis.py

# Generate test PCAP files
python tests/generate_test_data.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Tools

- **[Wireshark](https://www.wireshark.org/)**: Network protocol analyzer for manual analysis
- **[tshark](https://www.wireshark.org/docs/man-pages/tshark.html)**: Command-line network analysis
- **[dnscat2](https://github.com/iagox86/dnscat2)**: DNS tunneling tool
- **[iodine](https://github.com/yarrick/iodine)**: DNS tunnel implementation
- **[DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator)**: DNS exfiltration toolkit
- **[packetStrider](https://github.com/benjeems/packetStrider)**: PCAP analysis framework

## 📞 Support

If you encounter issues or have questions:

1. **Check the troubleshooting section** above
2. **Search existing issues** on GitHub
3. **Create a new issue** with:
   - Sample PCAP file (if not sensitive)
   - Command used and error output
   - Operating system and Python version
   - Expected vs. actual behavior

## 🏆 Acknowledgments

- **Scapy developers** for the excellent packet manipulation library
- **DNS RFC specifications** for protocol documentation
- **CTF community** for creative exfiltration techniques
- **Security researchers** for DNS covert channel research
- **Digital forensics community** for analysis methodologies

## 📚 References

- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
- [DNS Exfiltration Techniques](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)

---

**Happy hunting!** 🕵️‍♂️🔍
