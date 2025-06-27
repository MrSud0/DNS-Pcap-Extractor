#!/usr/bin/env python3
"""
Advanced DNS Exfiltration Analyzer

A comprehensive tool for analyzing DNS traffic and extracting exfiltrated data
from packet captures. Supports multiple encoding schemes and analysis methods.

Requirements:
    pip install scapy

Usage:
    python dns_analyzer.py [options] <pcap_file>
    python dns_analyzer.py -i capture.pcap -o analysis_results
    python dns_analyzer.py -i data.pcap --encoding base64 --domain evil.com
"""

import argparse
import base64
import binascii
import json
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import rdpcap, DNS, DNSQR, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

class DNSExfiltrationAnalyzer:
    def __init__(self, pcap_file, output_dir="dns_analysis", verbose=False):
        self.pcap_file = pcap_file
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.dns_requests = []
        self.statistics = defaultdict(int)
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Encoding methods
        self.encoding_methods = {
            'hex': self.decode_hex,
            'base64': self.decode_base64,
            'base32': self.decode_base32,
            'ascii': self.decode_ascii,
            'binary': self.decode_binary,
        }
        
        # Common suspicious patterns
        self.suspicious_patterns = [
            r'^[0-9a-fA-F]{8,}$',  # Long hex strings
            r'^[A-Za-z0-9+/]{10,}={0,2}$',  # Base64
            r'^[A-Z2-7]{8,}={0,6}$',  # Base32
            r'^[01]{16,}$',  # Binary
        ]
    
    def log(self, message, level="info"):
        """Enhanced logging with levels"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": "[*]",
            "success": "[+]", 
            "warning": "[!]",
            "error": "[-]"
        }.get(level, "[*]")
        
        print(f"{prefix} {message}")
        
        if self.verbose and level in ["warning", "error"]:
            print(f"    Time: {timestamp}")
    
    def extract_dns_requests(self, filter_domain=None, min_length=0):
        """
        Extract DNS requests with enhanced filtering
        
        Args:
            filter_domain (str): Only analyze requests to specific domain
            min_length (int): Minimum query length to consider
        """
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available - cannot process PCAP files", "error")
            return []
        
        try:
            self.log(f"Loading PCAP file: {self.pcap_file}")
            packets = rdpcap(str(self.pcap_file))
            self.log(f"Processing {len(packets)} packets...")
            
            dns_data = []
            seen_queries = set()
            
            for i, packet in enumerate(packets):
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    # Extract DNS query information
                    query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    if query.endswith('.'):
                        query = query[:-1]
                    
                    # Apply filters
                    if len(query) < min_length:
                        continue
                        
                    if filter_domain and filter_domain not in query:
                        continue
                    
                    # Avoid duplicates but track frequency
                    query_info = {
                        'query': query,
                        'timestamp': packet.time if hasattr(packet, 'time') else i,
                        'src_ip': packet[IP].src if packet.haslayer(IP) else 'unknown',
                        'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'unknown',
                    }
                    
                    dns_data.append(query_info)
                    seen_queries.add(query)
            
            self.dns_requests = dns_data
            self.statistics['total_packets'] = len(packets)
            self.statistics['dns_requests'] = len(dns_data)
            self.statistics['unique_queries'] = len(seen_queries)
            
            self.log(f"Found {len(dns_data)} DNS requests ({len(seen_queries)} unique)")
            return dns_data
            
        except Exception as e:
            self.log(f"Error reading PCAP file: {e}", "error")
            return []
    
    def analyze_query_patterns(self):
        """Analyze DNS queries for suspicious patterns"""
        self.log("Analyzing query patterns...")
        
        patterns_found = defaultdict(list)
        domain_stats = Counter()
        length_stats = Counter()
        
        for req in self.dns_requests:
            query = req['query']
            domain_stats[query.split('.')[-2:]] += 1  # Count by domain
            length_stats[len(query)] += 1
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.match(pattern, query.split('.')[0]):  # Check subdomain
                    patterns_found[pattern].append(query)
        
        # Save pattern analysis
        analysis = {
            'suspicious_patterns': dict(patterns_found),
            'domain_frequency': dict(domain_stats.most_common(20)),
            'length_distribution': dict(length_stats.most_common(20)),
            'statistics': dict(self.statistics)
        }
        
        analysis_file = self.output_dir / "pattern_analysis.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        self.log(f"Pattern analysis saved to: {analysis_file}")
        return patterns_found
    
    def extract_encoded_data(self, encoding_type='auto', domain_filter=None):
        """
        Extract potentially encoded data from DNS queries
        
        Args:
            encoding_type (str): Encoding type to look for ('auto', 'hex', 'base64', etc.)
            domain_filter (str): Filter by specific domain
        """
        self.log(f"Extracting encoded data (encoding: {encoding_type})...")
        
        extracted_data = []
        
        for req in self.dns_requests:
            query = req['query']
            
            # Apply domain filter
            if domain_filter and domain_filter not in query:
                continue
            
            # Split query into parts
            parts = query.split('.')
            
            for i, part in enumerate(parts):
                if len(part) < 4:  # Skip very short parts
                    continue
                
                # Try different encoding methods
                if encoding_type == 'auto':
                    for enc_name, decoder in self.encoding_methods.items():
                        result = decoder(part)
                        if result['success']:
                            extracted_data.append({
                                'original_query': query,
                                'encoded_part': part,
                                'position': i,
                                'encoding': enc_name,
                                'decoded_data': result['data'],
                                'decoded_text': result['text'],
                                'timestamp': req['timestamp'],
                                'src_ip': req['src_ip']
                            })
                            break
                else:
                    if encoding_type in self.encoding_methods:
                        result = self.encoding_methods[encoding_type](part)
                        if result['success']:
                            extracted_data.append({
                                'original_query': query,
                                'encoded_part': part,
                                'position': i,
                                'encoding': encoding_type,
                                'decoded_data': result['data'],
                                'decoded_text': result['text'],
                                'timestamp': req['timestamp'],
                                'src_ip': req['src_ip']
                            })
        
        self.log(f"Extracted {len(extracted_data)} encoded data segments")
        return extracted_data
    
    def decode_hex(self, data):
        """Decode hex-encoded data"""
        try:
            if len(data) % 2 != 0:
                return {'success': False, 'error': 'Odd length'}
            
            if not re.match(r'^[0-9a-fA-F]+$', data):
                return {'success': False, 'error': 'Invalid hex characters'}
            
            decoded_bytes = binascii.unhexlify(data)
            decoded_text = self.safe_decode_text(decoded_bytes)
            
            return {
                'success': True,
                'data': decoded_bytes,
                'text': decoded_text,
                'encoding': 'hex'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decode_base64(self, data):
        """Decode base64-encoded data"""
        try:
            # Add padding if necessary
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(data)
            decoded_text = self.safe_decode_text(decoded_bytes)
            
            return {
                'success': True,
                'data': decoded_bytes,
                'text': decoded_text,
                'encoding': 'base64'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decode_base32(self, data):
        """Decode base32-encoded data"""
        try:
            # Add padding if necessary
            missing_padding = len(data) % 8
            if missing_padding:
                data += '=' * (8 - missing_padding)
            
            decoded_bytes = base64.b32decode(data.upper())
            decoded_text = self.safe_decode_text(decoded_bytes)
            
            return {
                'success': True,
                'data': decoded_bytes,
                'text': decoded_text,
                'encoding': 'base32'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decode_ascii(self, data):
        """Decode ASCII-encoded data (character codes)"""
        try:
            # Look for patterns like "65656566" (ABCD in ASCII codes)
            if len(data) % 2 == 0 and re.match(r'^[0-9]+$', data):
                ascii_codes = [int(data[i:i+2]) for i in range(0, len(data), 2)]
                if all(32 <= code <= 126 for code in ascii_codes):  # Printable ASCII
                    decoded_text = ''.join(chr(code) for code in ascii_codes)
                    return {
                        'success': True,
                        'data': decoded_text.encode(),
                        'text': decoded_text,
                        'encoding': 'ascii'
                    }
            
            return {'success': False, 'error': 'Not ASCII encoded'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decode_binary(self, data):
        """Decode binary-encoded data"""
        try:
            if not re.match(r'^[01]+$', data):
                return {'success': False, 'error': 'Not binary'}
            
            if len(data) % 8 != 0:
                return {'success': False, 'error': 'Invalid binary length'}
            
            # Convert binary to bytes
            decoded_bytes = bytes(int(data[i:i+8], 2) for i in range(0, len(data), 8))
            decoded_text = self.safe_decode_text(decoded_bytes)
            
            return {
                'success': True,
                'data': decoded_bytes,
                'text': decoded_text,
                'encoding': 'binary'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def safe_decode_text(self, data):
        """Safely decode bytes to text"""
        try:
            text = data.decode('utf-8')
            return text if text.isprintable() else f"<binary:{len(data)} bytes>"
        except UnicodeDecodeError:
            try:
                text = data.decode('latin1')
                return text if text.isprintable() else f"<binary:{len(data)} bytes>"
            except:
                return f"<binary:{len(data)} bytes>"
    
    def reassemble_data(self, extracted_data, method='timestamp'):
        """
        Reassemble extracted data segments
        
        Args:
            extracted_data (list): List of extracted data segments
            method (str): Reassembly method ('timestamp', 'sequence', 'domain')
        """
        self.log(f"Reassembling data using method: {method}")
        
        if method == 'timestamp':
            # Sort by timestamp
            sorted_data = sorted(extracted_data, key=lambda x: x['timestamp'])
        elif method == 'sequence':
            # Try to find sequence indicators in domain names
            sorted_data = sorted(extracted_data, key=lambda x: self.extract_sequence_number(x['original_query']))
        else:
            sorted_data = extracted_data
        
        # Group by encoding type
        by_encoding = defaultdict(list)
        for item in sorted_data:
            by_encoding[item['encoding']].append(item)
        
        reassembled_results = {}
        
        for encoding, items in by_encoding.items():
            try:
                # Combine all decoded bytes
                combined_bytes = b''.join(item['decoded_data'] for item in items)
                combined_text = self.safe_decode_text(combined_bytes)
                
                reassembled_results[encoding] = {
                    'segments': len(items),
                    'total_bytes': len(combined_bytes),
                    'combined_data': combined_bytes,
                    'combined_text': combined_text,
                    'segments_info': items
                }
                
                self.log(f"Reassembled {len(items)} {encoding} segments ({len(combined_bytes)} bytes)")
                
            except Exception as e:
                self.log(f"Error reassembling {encoding} data: {e}", "warning")
        
        return reassembled_results
    
    def extract_sequence_number(self, query):
        """Extract sequence number from DNS query"""
        # Look for common sequence patterns like seq1.data.com, 001.data.com, etc.
        patterns = [
            r'seq(\d+)',
            r'(\d+)\..*',
            r'.*-(\d+)\.',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, query)
            if match:
                return int(match.group(1))
        
        return 0  # Default sequence
    
    def save_results(self, extracted_data, reassembled_data):
        """Save analysis results to files"""
        self.log("Saving analysis results...")
        
        # Save raw DNS requests
        requests_file = self.output_dir / "dns_requests.json"
        with open(requests_file, 'w') as f:
            json.dump(self.dns_requests, f, indent=2, default=str)
        
        # Save extracted data
        extracted_file = self.output_dir / "extracted_data.json"
        with open(extracted_file, 'w') as f:
            json.dump(extracted_data, f, indent=2, default=str)
        
        # Save reassembled data
        reassembled_file = self.output_dir / "reassembled_data.json"
        with open(reassembled_file, 'w') as f:
            json.dump(reassembled_data, f, indent=2, default=str)
        
        # Save human-readable summary
        summary_file = self.output_dir / "analysis_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("DNS EXFILTRATION ANALYSIS SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"PCAP File: {self.pcap_file}\n")
            f.write(f"Total Packets: {self.statistics.get('total_packets', 0)}\n")
            f.write(f"DNS Requests: {self.statistics.get('dns_requests', 0)}\n")
            f.write(f"Unique Queries: {self.statistics.get('unique_queries', 0)}\n")
            f.write(f"Extracted Segments: {len(extracted_data)}\n\n")
            
            if reassembled_data:
                f.write("REASSEMBLED DATA:\n")
                f.write("-" * 30 + "\n")
                for encoding, data in reassembled_data.items():
                    f.write(f"\n{encoding.upper()} Data:\n")
                    f.write(f"  Segments: {data['segments']}\n")
                    f.write(f"  Total Size: {data['total_bytes']} bytes\n")
                    f.write(f"  Content Preview: {data['combined_text'][:200]}...\n")
            
            if extracted_data:
                f.write("\nEXTRACTED SEGMENTS:\n")
                f.write("-" * 30 + "\n")
                for i, item in enumerate(extracted_data[:10]):  # Show first 10
                    f.write(f"\nSegment {i+1}:\n")
                    f.write(f"  Query: {item['original_query']}\n")
                    f.write(f"  Encoding: {item['encoding']}\n")
                    f.write(f"  Decoded: {item['decoded_text'][:100]}...\n")
        
        # Save decoded binary files
        for encoding, data in reassembled_data.items():
            if len(data['combined_data']) > 0:
                binary_file = self.output_dir / f"reassembled_{encoding}.bin"
                with open(binary_file, 'wb') as f:
                    f.write(data['combined_data'])
                self.log(f"Saved binary data: {binary_file}")
        
        self.log(f"All results saved to: {self.output_dir}")
    
    def generate_report(self, extracted_data, reassembled_data):
        """Generate comprehensive analysis report"""
        self.log("Generating analysis report...")
        
        print("\n" + "=" * 60)
        print("DNS EXFILTRATION ANALYSIS REPORT")
        print("=" * 60)
        
        print(f"\nFile: {self.pcap_file}")
        print(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\nStatistics:")
        print(f"  Total Packets: {self.statistics.get('total_packets', 0)}")
        print(f"  DNS Requests: {self.statistics.get('dns_requests', 0)}")
        print(f"  Unique Queries: {self.statistics.get('unique_queries', 0)}")
        print(f"  Extracted Segments: {len(extracted_data)}")
        
        if extracted_data:
            print(f"\nEncoding Distribution:")
            encoding_counts = Counter(item['encoding'] for item in extracted_data)
            for encoding, count in encoding_counts.most_common():
                print(f"  {encoding}: {count} segments")
        
        if reassembled_data:
            print(f"\nReassembled Data:")
            for encoding, data in reassembled_data.items():
                print(f"  {encoding.upper()}:")
                print(f"    Segments: {data['segments']}")
                print(f"    Size: {data['total_bytes']} bytes")
                if data['combined_text'] and len(data['combined_text']) < 200:
                    print(f"    Content: {data['combined_text']}")
                else:
                    print(f"    Preview: {data['combined_text'][:100]}...")
    
    def analyze(self, encoding='auto', domain_filter=None, min_length=4, reassemble_method='timestamp'):
        """
        Main analysis function
        
        Args:
            encoding (str): Encoding type to analyze
            domain_filter (str): Filter by specific domain
            min_length (int): Minimum query length
            reassemble_method (str): Data reassembly method
        """
        self.log("Starting DNS exfiltration analysis...")
        
        # Extract DNS requests
        dns_data = self.extract_dns_requests(domain_filter, min_length)
        if not dns_data:
            self.log("No DNS data found", "error")
            return False
        
        # Analyze patterns
        patterns = self.analyze_query_patterns()
        
        # Extract encoded data
        extracted_data = self.extract_encoded_data(encoding, domain_filter)
        
        # Reassemble data
        reassembled_data = {}
        if extracted_data:
            reassembled_data = self.reassemble_data(extracted_data, reassemble_method)
        
        # Save results
        self.save_results(extracted_data, reassembled_data)
        
        # Generate report
        self.generate_report(extracted_data, reassembled_data)
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description="Advanced DNS Exfiltration Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dns_analyzer.py capture.pcap                    # Basic analysis
  python dns_analyzer.py -i data.pcap -o results       # Custom output dir
  python dns_analyzer.py -i data.pcap --encoding hex    # Force hex decoding
  python dns_analyzer.py -i data.pcap --domain evil.com # Filter by domain
  python dns_analyzer.py -i data.pcap --min-length 10   # Min query length
  python dns_analyzer.py -i data.pcap --reassemble seq  # Sequence-based reassembly
        """
    )
    
    parser.add_argument(
        'pcap_file',
        nargs='?',
        help='PCAP file to analyze (default: capture.pcap)'
    )
    
    parser.add_argument(
        '-i', '--input',
        help='Input PCAP file'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='dns_analysis',
        help='Output directory (default: dns_analysis)'
    )
    
    parser.add_argument(
        '--encoding',
        choices=['auto', 'hex', 'base64', 'base32', 'ascii', 'binary'],
        default='auto',
        help='Encoding type to analyze (default: auto)'
    )
    
    parser.add_argument(
        '--domain',
        help='Filter DNS queries by domain'
    )
    
    parser.add_argument(
        '--min-length',
        type=int,
        default=4,
        help='Minimum query length to analyze (default: 4)'
    )
    
    parser.add_argument(
        '--reassemble',
        choices=['timestamp', 'sequence', 'none'],
        default='timestamp',
        help='Data reassembly method (default: timestamp)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Determine input file
    pcap_file = args.input or args.pcap_file or 'capture.pcap'
    
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found!")
        print("Please specify a valid PCAP file.")
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is required but not installed.")
        print("Install with: pip install scapy")
        sys.exit(1)
    
    # Create analyzer and run analysis
    analyzer = DNSExfiltrationAnalyzer(pcap_file, args.output, args.verbose)
    
    try:
        success = analyzer.analyze(
            encoding=args.encoding,
            domain_filter=args.domain,
            min_length=args.min_length,
            reassemble_method=args.reassemble
        )
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n[-] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
