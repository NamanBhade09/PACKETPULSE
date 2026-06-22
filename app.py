import os
import sys
import time
import threading
import uuid
import socket
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, jsonify, request, render_template, send_file
from scapy.all import sniff, conf, wrpcap, Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Application state
capture_state = {
    'running': False,
    'interface': None,
    'filter': "",
    'packets': [],          # List of parsed packets (dictionaries)
    'raw_packets': [],      # List of Scapy Packet objects for export
    'alerts': [],           # Security Alerts triggered
    'stats': {
        'total': 0,
        'protocols': {},
        'sources': {},
        'destinations': {},
        'bytes_transferred': 0,
        'start_time': None
    }
}

lock = threading.Lock()
sniffer_thread = None
stop_event = threading.Event()

# Reverse DNS Lookup Cache & Thread Pool
dns_cache = {}
dns_lock = threading.Lock()
dns_executor = ThreadPoolExecutor(max_workers=5)

# IDS Trackers
port_scan_tracker = {}
syn_flood_tracker = {}

def resolve_ip_async(ip):
    """Schedules an IP for asynchronous reverse DNS resolution."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"):
        return
        
    with dns_lock:
        if ip in dns_cache:
            return
        # Mark as resolving to prevent duplicate tasks
        dns_cache[ip] = "resolving..."
        
    def resolve_task(ip_addr):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_addr)
            with dns_lock:
                dns_cache[ip_addr] = hostname
        except Exception:
            with dns_lock:
                dns_cache[ip_addr] = None # Resolution failed
                
    dns_executor.submit(resolve_task, ip)

def get_resolved_ip(ip):
    """Retrieves resolved hostname from cache if available."""
    with dns_lock:
        name = dns_cache.get(ip)
        if name and name != "resolving...":
            return f"{ip} ({name})"
        return ip

def extract_tls_sni(payload_bytes):
    """Parses raw TLS handshake packets to extract Server Name Indication (SNI)."""
    try:
        # Check TLS Record header: Handshake (0x16), Version (0x03 0x01/02/03)
        if len(payload_bytes) < 45 or payload_bytes[0] != 0x16 or payload_bytes[1] != 0x03:
            return None
            
        # Handshake Type: Client Hello (0x01)
        if payload_bytes[5] != 0x01:
            return None
            
        # Parse variable-length Session ID
        session_id_len = payload_bytes[43]
        idx = 44 + session_id_len
        
        # Cipher Suites Length & Cipher Suites
        if idx + 2 > len(payload_bytes): return None
        cipher_suites_len = int.from_bytes(payload_bytes[idx:idx+2], byteorder='big')
        idx += 2 + cipher_suites_len
        
        # Compression Methods
        if idx + 1 > len(payload_bytes): return None
        compression_len = payload_bytes[idx]
        idx += 1 + compression_len
        
        # Extensions Length
        if idx + 2 > len(payload_bytes): return None
        extensions_len = int.from_bytes(payload_bytes[idx:idx+2], byteorder='big')
        idx += 2
        
        end_idx = idx + extensions_len
        if end_idx > len(payload_bytes):
            end_idx = len(payload_bytes)
            
        # Iterate over extensions
        while idx + 4 <= end_idx:
            ext_type = int.from_bytes(payload_bytes[idx:idx+2], byteorder='big')
            ext_len = int.from_bytes(payload_bytes[idx+2:idx+4], byteorder='big')
            idx += 4
            
            if ext_type == 0: # SNI Extension
                if idx + 5 <= len(payload_bytes):
                    server_name_type = payload_bytes[idx+2]
                    server_name_len = int.from_bytes(payload_bytes[idx+3:idx+5], byteorder='big')
                    if server_name_type == 0 and idx + 5 + server_name_len <= len(payload_bytes):
                        sni = payload_bytes[idx+5:idx+5+server_name_len].decode('utf-8', errors='ignore')
                        return sni
            idx += ext_len
    except Exception:
        pass
    return None

def decode_payload_properly(pkt, proto, payload_bytes):
    """Deep dissects and decodes application payloads into structured and readable models."""
    if not payload_bytes:
        return {"type": "empty", "content": "No payload"}

    # Determine if payload is text or binary
    printable_chars = bytearray(c for c in payload_bytes if 32 <= c <= 126 or c in (10, 13, 9))
    is_printable = (len(printable_chars) / len(payload_bytes)) > 0.85 if payload_bytes else False
    
    # 1. HTTP Protocol Dissector
    if proto == "HTTP":
        try:
            parts = payload_bytes.split(b"\r\n\r\n", 1)
            header_part = parts[0].decode('utf-8', errors='ignore')
            body_part = parts[1] if len(parts) > 1 else b""
            
            headers = {}
            lines = header_part.split("\r\n")
            request_line = lines[0]
            
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
                    
            body_text = ""
            body_json = None
            if body_part:
                body_text = body_part.decode('utf-8', errors='replace')
                # Check for JSON body
                if body_text.strip().startswith(("{", "[")):
                    import json
                    try:
                        body_json = json.loads(body_text)
                    except:
                        pass
                        
            return {
                "type": "http",
                "request_line": request_line,
                "headers": headers,
                "body": body_text,
                "body_json": body_json
            }
        except Exception:
            pass

    # 2. DNS Protocol Dissector
    if proto == "DNS" and pkt.haslayer(DNS):
        try:
            dns = pkt[DNS]
            queries = []
            if dns.qd:
                q = dns.qd
                queries.append({
                    "name": q.qname.decode('utf-8', errors='ignore') if isinstance(q.qname, bytes) else str(q.qname),
                    "type": q.qtype,
                    "class": q.qclass
                })
            answers = []
            
            # Helper to parse DNS RR list
            if dns.an:
                curr = dns.an
                # Scapy links RRs as nested payload layers
                while curr:
                    # Break loop if layer is not DNS Resource Record
                    if not hasattr(curr, 'rrname'):
                        break
                    rdata = curr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode('utf-8', errors='ignore')
                    answers.append({
                        "name": curr.rrname.decode('utf-8', errors='ignore') if isinstance(curr.rrname, bytes) else str(curr.rrname),
                        "type": curr.type,
                        "rdata": str(rdata),
                        "ttl": curr.ttl
                    })
                    curr = curr.payload if hasattr(curr, 'payload') and isinstance(curr.payload, Packet) else None
                    
            return {
                "type": "dns",
                "qr": "Response" if dns.qr == 1 else "Query",
                "rcode": dns.rcode,
                "queries": queries,
                "answers": answers
            }
        except Exception:
            pass

    # 3. JSON Plaintext Check
    if is_printable:
        try:
            text = payload_bytes.decode('utf-8')
            if text.strip().startswith(("{", "[")):
                import json
                return {
                    "type": "json",
                    "content": json.loads(text)
                }
            return {
                "type": "text",
                "content": text
            }
        except Exception:
            pass
            
    # 4. Binary representation with text equivalent
    return {
        "type": "binary",
        "length": len(payload_bytes),
        "hex": payload_bytes.hex(),
        "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in payload_bytes)
    }

def check_ids_rules(parsed_pkt, raw_pkt):
    """IDS Engine: Scans live packet structures against security anomaly rules."""
    global capture_state, port_scan_tracker, syn_flood_tracker
    src = parsed_pkt['src']
    dst = parsed_pkt['dst']
    now = time.time()
    
    # Rule 1: Cleartext Credentials exposure
    payload = parsed_pkt.get('payload', '')
    if isinstance(payload, str) and payload:
        cred_keys = ['password=', 'passwd=', 'pwd=', 'pass=', 'login_password', 'secret=']
        if any(k in payload.lower() for k in cred_keys):
            alert = {
                'id': str(uuid.uuid4()),
                'timestamp': now,
                'packet_id': parsed_pkt['id'],
                'severity': 'HIGH',
                'type': 'Cleartext Credentials Exposed',
                'summary': f"Potential plain text credentials detected from {src} to {dst}"
            }
            capture_state['alerts'].append(alert)
            
    # Rule 2: Port Scanning Detection (10+ different destination ports in 10s)
    if raw_pkt.haslayer(TCP):
        tcp = raw_pkt[TCP]
        dport = tcp.dport
        
        if src not in port_scan_tracker:
            port_scan_tracker[src] = {'ports': {dport}, 'start_time': now}
        else:
            tracker = port_scan_tracker[src]
            if now - tracker['start_time'] < 10:
                tracker['ports'].add(dport)
                if len(tracker['ports']) >= 10:
                    alert = {
                        'id': str(uuid.uuid4()),
                        'timestamp': now,
                        'packet_id': parsed_pkt['id'],
                        'severity': 'MEDIUM',
                        'type': 'Port Scan Detected',
                        'summary': f"Host {src} hit {len(tracker['ports'])} ports on {dst} within 10 seconds"
                    }
                    # Alert deduplication
                    if not any(a['type'] == 'Port Scan Detected' and a['summary'].startswith(f"Host {src}") and now - a['timestamp'] < 15 for a in capture_state['alerts']):
                        capture_state['alerts'].append(alert)
            else:
                port_scan_tracker[src] = {'ports': {dport}, 'start_time': now}
                
    # Rule 3: DoS / SYN Flood Check (30+ SYN packets in 5 seconds)
    if raw_pkt.haslayer(TCP) and raw_pkt[TCP].flags == 'S':
        if src not in syn_flood_tracker:
            syn_flood_tracker[src] = {'count': 1, 'start_time': now}
        else:
            tracker = syn_flood_tracker[src]
            if now - tracker['start_time'] < 5:
                tracker['count'] += 1
                if tracker['count'] >= 30:
                    alert = {
                        'id': str(uuid.uuid4()),
                        'timestamp': now,
                        'packet_id': parsed_pkt['id'],
                        'severity': 'HIGH',
                        'type': 'SYN Flood Alert (DoS)',
                        'summary': f"Host {src} sent {tracker['count']} SYN packets in 5 seconds (Potential DoS)"
                    }
                    if not any(a['type'] == 'SYN Flood Alert (DoS)' and a['summary'].startswith(f"Host {src}") and now - a['timestamp'] < 15 for a in capture_state['alerts']):
                        capture_state['alerts'].append(alert)
            else:
                syn_flood_tracker[src] = {'count': 1, 'start_time': now}

def get_friendly_interfaces():
    """Returns a list of available network interfaces."""
    interfaces = []
    for iface_id, iface in conf.ifaces.items():
        name = iface.name
        desc = iface.description or iface.name
        ip = iface.ip or ""
        
        interfaces.append({
            'id': name,
            'name': f"{desc} ({ip})" if ip else desc,
            'ip': ip,
            'is_loopback': "loopback" in desc.lower() or "loopback" in name.lower() or ip == "127.0.0.1"
        })
    interfaces.sort(key=lambda x: (not x['ip'], x['is_loopback']))
    return interfaces

def dissect_packet(pkt, pkt_id, timestamp):
    """Deeply dissects a Scapy packet into a structured dictionary."""
    details = {}
    summary = pkt.summary()
    proto = "UNKNOWN"
    length = len(pkt)
    
    # Layer 2: Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        details['Ethernet'] = {
            'src': eth.src,
            'dst': eth.dst,
            'type': hex(eth.type)
        }
        
    # Layer 2: ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        proto = "ARP"
        op_map = {1: "who-has (request)", 2: "is-at (reply)"}
        details['ARP'] = {
            'op': op_map.get(arp.op, str(arp.op)),
            'hwsrc': arp.hwsrc,
            'psrc': arp.psrc,
            'hwdst': arp.hwdst,
            'pdst': arp.pdst
        }
        src_ip = arp.psrc
        dst_ip = arp.pdst
        resolve_ip_async(src_ip)
        resolve_ip_async(dst_ip)

    # Layer 3: IPv4
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        proto = "IPv4"
        details['IPv4'] = {
            'version': ip.version,
            'ihl': ip.ihl,
            'tos': ip.tos,
            'len': ip.len,
            'id': ip.id,
            'flags': str(ip.flags),
            'frag': ip.frag,
            'ttl': ip.ttl,
            'proto': ip.proto,
            'chksum': hex(ip.chksum) if ip.chksum else "None",
            'src': ip.src,
            'dst': ip.dst
        }
        src_ip = ip.src
        dst_ip = ip.dst
        resolve_ip_async(src_ip)
        resolve_ip_async(dst_ip)
        
        # Layer 4 within IPv4
        if ip.proto == 6 or pkt.haslayer(TCP):
            proto = "TCP"
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                details['TCP'] = {
                    'sport': tcp.sport,
                    'dport': tcp.dport,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'dataofs': tcp.dataofs,
                    'reserved': tcp.reserved,
                    'flags': str(tcp.flags),
                    'window': tcp.window,
                    'chksum': hex(tcp.chksum) if tcp.chksum else "None"
                }
        elif ip.proto == 17 or pkt.haslayer(UDP):
            proto = "UDP"
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                details['UDP'] = {
                    'sport': udp.sport,
                    'dport': udp.dport,
                    'len': udp.len,
                    'chksum': hex(udp.chksum) if udp.chksum else "None"
                }
        elif ip.proto == 1 or pkt.haslayer(ICMP):
            proto = "ICMP"
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                details['ICMP'] = {
                    'type': icmp.type,
                    'code': icmp.code,
                    'chksum': hex(icmp.chksum) if icmp.chksum else "None"
                }

    # Layer 3: IPv6
    elif pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        proto = "IPv6"
        details['IPv6'] = {
            'version': ipv6.version,
            'tc': ipv6.tc,
            'fl': ipv6.fl,
            'plen': ipv6.plen,
            'nh': ipv6.nh,
            'hlim': ipv6.hlim,
            'src': ipv6.src,
            'dst': ipv6.dst
        }
        src_ip = ipv6.src
        dst_ip = ipv6.dst
        resolve_ip_async(src_ip)
        resolve_ip_async(dst_ip)
        
        # Layer 4 within IPv6
        if ipv6.nh == 6 or pkt.haslayer(TCP):
            proto = "TCP"
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                details['TCP'] = {
                    'sport': tcp.sport,
                    'dport': tcp.dport,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'flags': str(tcp.flags),
                    'window': tcp.window
                }
        elif ipv6.nh == 17 or pkt.haslayer(UDP):
            proto = "UDP"
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                details['UDP'] = {
                    'sport': udp.sport,
                    'dport': udp.dport,
                    'len': udp.len
                }

    else:
        src_ip = pkt.src if hasattr(pkt, 'src') else "0.0.0.0"
        dst_ip = pkt.dst if hasattr(pkt, 'dst') else "0.0.0.0"

    # Layer 7: DNS Check
    if pkt.haslayer(DNS):
        proto = "DNS"
        dns = pkt[DNS]
        details['DNS'] = {
            'id': dns.id,
            'qr': dns.qr,
            'opcode': dns.opcode,
            'aa': dns.aa,
            'tc': dns.tc,
            'rd': dns.rd,
            'ra': dns.ra,
            'rcode': dns.rcode,
            'qdcount': dns.qdcount,
            'ancount': dns.ancount
        }
        if dns.qd:
            details['DNS']['query'] = dns.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)

    # Walk bytes for Hex / ASCII
    raw_bytes = bytes(pkt)
    hex_dump = []
    ascii_dump = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i+16]
        hex_parts = [f"{b:02x}" for b in chunk]
        if len(hex_parts) < 16:
            hex_parts += ["  "] * (16 - len(hex_parts))
        hex_dump.append(" ".join(hex_parts))
        
        ascii_parts = []
        for b in chunk:
            if 32 <= b <= 126:
                ascii_parts.append(chr(b))
            else:
                ascii_parts.append(".")
        ascii_dump.append("".join(ascii_parts))

    # Read payload bytes
    payload_bytes = b""
    if pkt.haslayer('Raw'):
        payload_bytes = bytes(pkt['Raw'].load)
    elif pkt.haslayer(TCP) and pkt[TCP].payload and not isinstance(pkt[TCP].payload, Packet):
        payload_bytes = bytes(pkt[TCP].payload)
    elif pkt.haslayer(UDP) and pkt[UDP].payload and not isinstance(pkt[UDP].payload, Packet):
        payload_bytes = bytes(pkt[UDP].payload)

    payload_text = ""
    # Protocol Specific Identifications in TCP/UDP Payload
    if payload_bytes:
        payload_text = payload_bytes.decode('utf-8', errors='replace')
        if pkt.haslayer(TCP):
            if any(sig in payload_bytes for sig in [b"GET ", b"POST ", b"HTTP/1."]):
                proto = "HTTP"
            elif payload_bytes.startswith(b"\x16\x03"):
                proto = "TLS"
                sni = extract_tls_sni(payload_bytes)
                if sni:
                    summary = f"TLS Client Hello SNI: {sni}"

    # Get structured payload details
    decoded_payload = decode_payload_properly(pkt, proto, payload_bytes)

    return {
        'id': pkt_id,
        'timestamp': timestamp,
        'src': src_ip,
        'dst': dst_ip,
        'protocol': proto,
        'length': length,
        'summary': summary,
        'details': details,
        'hex': hex_dump,
        'ascii': ascii_dump,
        'payload': payload_text,
        'decoded_payload': decoded_payload
    }

def packet_handler(pkt):
    """Callback function executed on every sniffed packet."""
    global capture_state
    
    if stop_event.is_set():
        return
        
    with lock:
        if not capture_state['running']:
            return
            
        timestamp = time.time()
        pkt_id = str(uuid.uuid4())
        
        # Dissect
        parsed = dissect_packet(pkt, pkt_id, timestamp)
        
        # Security alerting
        check_ids_rules(parsed, pkt)
        
        if len(capture_state['packets']) >= 5000:
            capture_state['packets'].pop(0)
            capture_state['raw_packets'].pop(0)
            
        capture_state['packets'].append(parsed)
        capture_state['raw_packets'].append(pkt)
        
        # Update metrics
        capture_state['stats']['total'] += 1
        capture_state['stats']['bytes_transferred'] += parsed['length']
        
        proto = parsed['protocol']
        capture_state['stats']['protocols'][proto] = capture_state['stats']['protocols'].get(proto, 0) + 1
        
        src = parsed['src']
        capture_state['stats']['sources'][src] = capture_state['stats']['sources'].get(src, 0) + 1
        
        dst = parsed['dst']
        capture_state['stats']['destinations'][dst] = capture_state['stats']['destinations'].get(dst, 0) + 1

def run_sniffing():
    """Background sniffing function."""
    global capture_state
    iface = capture_state['interface']
    filt = capture_state['filter'] or None
    
    print(f"[*] Thread started sniffing on interface: '{iface}' with BPF filter: '{filt}'")
    
    try:
        while not stop_event.is_set() and capture_state['running']:
            sniff(
                iface=iface,
                filter=filt,
                prn=packet_handler,
                store=False,
                timeout=1
            )
    except Exception as e:
        print(f"[!] Error inside sniffer thread: {e}", file=sys.stderr)
        with lock:
            capture_state['running'] = False

# HTTP Routing
@app.route('/')
def index():
    return render_template('index.html')

# Mock route to test cleartext login credentials alert
@app.route('/mock-login', methods=['POST'])
def mock_login():
    return jsonify({"status": "received"})

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    return jsonify(get_friendly_interfaces())

@app.route('/api/status', methods=['GET'])
def get_status():
    with lock:
        return jsonify({
            'running': capture_state['running'],
            'interface': capture_state['interface'],
            'filter': capture_state['filter']
        })

@app.route('/api/start', methods=['POST'])
def start_capture():
    global sniffer_thread, stop_event, port_scan_tracker, syn_flood_tracker
    
    data = request.json or {}
    iface = data.get('interface')
    filt = data.get('filter', "")
    
    if not iface:
        return jsonify({'error': 'Interface is required'}), 400
        
    with lock:
        if capture_state['running']:
            return jsonify({'error': 'Capture already running'}), 400
            
        stop_event.clear()
        capture_state['running'] = True
        capture_state['interface'] = iface
        capture_state['filter'] = filt
        
        # Reset state & trackers
        capture_state['packets'] = []
        capture_state['raw_packets'] = []
        capture_state['alerts'] = []
        port_scan_tracker = {}
        syn_flood_tracker = {}
        
        capture_state['stats'] = {
            'total': 0,
            'protocols': {},
            'sources': {},
            'destinations': {},
            'bytes_transferred': 0,
            'start_time': time.time()
        }
        
        sniffer_thread = threading.Thread(target=run_sniffing, daemon=True)
        sniffer_thread.start()
        
    return jsonify({'status': 'Capture started'})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    global sniffer_thread, stop_event
    with lock:
        if not capture_state['running']:
            return jsonify({'error': 'Capture is not running'}), 400
            
        capture_state['running'] = False
        stop_event.set()
        
    if sniffer_thread:
        sniffer_thread.join(timeout=2.0)
        
    return jsonify({'status': 'Capture stopped'})

@app.route('/api/packets', methods=['GET'])
def get_packets():
    with lock:
        last_id = request.args.get('after')
        packets_to_send = []
        
        if last_id:
            found = False
            for p in capture_state['packets']:
                if found:
                    packets_to_send.append(p)
                elif p['id'] == last_id:
                    found = True
            if not found:
                packets_to_send = capture_state['packets']
        else:
            packets_to_send = capture_state['packets']
            
        # Add resolved DNS hostname annotations to packets in list response
        slim_packets = []
        for p in packets_to_send:
            slim_packets.append({
                'id': p['id'],
                'timestamp': p['timestamp'],
                'src': get_resolved_ip(p['src']),
                'dst': get_resolved_ip(p['dst']),
                'protocol': p['protocol'],
                'length': p['length'],
                'summary': p['summary']
            })
            
        duration = 0
        if capture_state['stats']['start_time']:
            end = time.time() if capture_state['running'] else (time.time() if not capture_state['packets'] else capture_state['packets'][-1]['timestamp'])
            duration = max(0, end - capture_state['stats']['start_time'])
            
        # Resolve names for top stats lists as well
        resolved_sources = {get_resolved_ip(k): v for k, v in capture_state['stats']['sources'].items()}
        resolved_dests = {get_resolved_ip(k): v for k, v in capture_state['stats']['destinations'].items()}
            
        return jsonify({
            'packets': slim_packets,
            'running': capture_state['running'],
            'duration': duration,
            'alerts': capture_state['alerts'],
            'stats': {
                'total': capture_state['stats']['total'],
                'protocols': capture_state['stats']['protocols'],
                'sources': dict(sorted(resolved_sources.items(), key=lambda item: item[1], reverse=True)[:5]),
                'destinations': dict(sorted(resolved_dests.items(), key=lambda item: item[1], reverse=True)[:5]),
                'bytes_transferred': capture_state['stats']['bytes_transferred']
            }
        })

@app.route('/api/packet/<pkt_id>', methods=['GET'])
def get_packet_details(pkt_id):
    with lock:
        for p in capture_state['packets']:
            if p['id'] == pkt_id:
                # Add resolved IPs to details before sending
                resp = p.copy()
                resp['src_resolved'] = get_resolved_ip(p['src'])
                resp['dst_resolved'] = get_resolved_ip(p['dst'])
                return jsonify(resp)
        return jsonify({'error': 'Packet not found'}), 404

@app.route('/api/export', methods=['GET'])
def export_pcap():
    with lock:
        if not capture_state['raw_packets']:
            return jsonify({'error': 'No packets captured to export'}), 400
            
        temp_filename = f"capture_{int(time.time())}.pcap"
        temp_filepath = os.path.join(os.getcwd(), temp_filename)
        
        try:
            wrpcap(temp_filepath, capture_state['raw_packets'])
        except Exception as e:
            return jsonify({'error': f'Failed to write PCAP: {e}'}), 500
            
    try:
        return send_file(temp_filepath, as_attachment=True, download_name="live_capture.pcap")
    finally:
        def cleanup():
            time.sleep(2)
            try:
                if os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
            except Exception:
                pass
        threading.Thread(target=cleanup, daemon=True).start()

if __name__ == '__main__':
    print("[*] Starting PacketPulse Deep Packet Analyzer Server...")
    print("[*] Ensuring administrative access controls...")
    
    is_admin = False
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        pass
        
    if not is_admin:
        print("[!] WARNING: Running without Administrative privileges. Live sniffing might fail with socket errors.")
        
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
