import argparse
import json
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime, timezone

try:
    from scapy.all import (
        rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, Ether
    )
except ImportError:
    print("Error: scapy is not installed. Install it with:")
    print("  pip install scapy --break-system-packages")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_engine import parse_tls_record, tls_version_name


ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply",
}

APP_PORT_TCP = {
    80: "HTTP", 443: "HTTPS/TLS", 22: "SSH", 21: "FTP", 25: "SMTP",
    110: "POP3", 143: "IMAP", 3389: "RDP", 23: "Telnet", 445: "SMB",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}
APP_PORT_UDP = {
    53: "DNS", 123: "NTP", 67: "DHCP", 68: "DHCP", 5353: "mDNS",
    443: "QUIC/HTTP3", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP",
    500: "IKE/IPsec", 1900: "SSDP",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def classify_app(proto, sport, dport):
    table = APP_PORT_TCP if proto == "TCP" else APP_PORT_UDP
    if dport in table:
        return table[dport]
    if sport in table:
        return table[sport]
    return f"{proto}/other"


def human_bytes(n):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")[:-3]
    except Exception:
        return str(ts)


def fmt_time_short(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%H:%M:%S")
    except Exception:
        return str(ts)




class TCPStream:
    def __init__(self, key):
        self.key = key  
        self.first_seen = None
        self.last_seen = None
        self.packets = 0
        self.bytes = 0
        self.syn = 0
        self.synack = 0
        self.fin = 0
        self.rst = 0
        self.rst_events = []          
        self.retrans = 0
        self.retrans_evidence = []
        self.dup_ack = 0
        self.ooo = 0
        self.ooo_evidence = []
        self._seen_segments = {0: set(), 1: set()}   
        self._max_seq = {0: None, 1: None}
        self._last_ack = {0: None, 1: None}
        self.handshake_syn_seen = False
        self.handshake_synack_seen = False
        self.handshake_ack_seen = False

    def side_of(self, ip, port):
        return 0 if (ip, port) == self.key[0] else 1

    def update(self, ip, port, flags, seq, ack, paylen, ts, idx):
        side = self.side_of(ip, port)
        self.packets += 1
        self.bytes += paylen
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        fs = str(flags)
        is_syn = "S" in fs and "A" not in fs
        is_synack = "S" in fs and "A" in fs
        is_fin = "F" in fs
        is_rst = "R" in fs
        is_pure_ack = fs == "A" and paylen == 0

        if is_syn:
            self.syn += 1
            self.handshake_syn_seen = True
        if is_synack:
            self.synack += 1
            self.handshake_synack_seen = True
        if is_fin:
            self.fin += 1
        if is_rst:
            self.rst += 1
            self.rst_events.append((ts, idx, side))
        if is_pure_ack and self.handshake_synack_seen and not self.handshake_ack_seen:
            self.handshake_ack_seen = True

        if paylen > 0:
            seg = (seq, paylen)
            if seg in self._seen_segments[side]:
                self.retrans += 1
                if len(self.retrans_evidence) < 10:
                    self.retrans_evidence.append(idx)
            else:
                self._seen_segments[side].add(seg)
                mx = self._max_seq[side]
                if mx is not None and seq < mx:
                    self.ooo += 1
                    if len(self.ooo_evidence) < 10:
                        self.ooo_evidence.append(idx)
                self._max_seq[side] = max(mx or 0, seq + paylen)
        elif is_pure_ack:
            if self._last_ack[side] is not None and self._last_ack[side] == ack:
                self.dup_ack += 1
            self._last_ack[side] = ack

    def endpoints_str(self):
        (ip1, p1), (ip2, p2) = self.key
        return f"{ip1}:{p1} <-> {ip2}:{p2}"

    def handshake_status(self):
        if self.handshake_syn_seen and self.handshake_synack_seen and self.handshake_ack_seen:
            return "Complete (3-way handshake OK)"
        if self.handshake_syn_seen and not self.handshake_synack_seen:
            return "SYN sent, no SYN/ACK observed"
        if self.handshake_synack_seen and not self.handshake_ack_seen:
            return "SYN/ACK observed, no final ACK"
        if not self.handshake_syn_seen:
            return "No handshake captured (mid-stream capture)"
        return "Incomplete"




class PcapAnalyzer:
    def __init__(self, path, top_n=15):
        self.path = path
        self.top_n = top_n
        self.packets = None

        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None
        self.protocols = Counter()
        self.ip_bytes = Counter()        
        self.ip_src_bytes = Counter()
        self.ip_src_pkts = Counter()
        self.ip_dst_pkts = Counter()
        self.conversations_pkts = Counter()
        self.conversations_bytes = Counter()
        self.app_classes = Counter()       

        self.tcp_streams = {}              
        self.tcp_ports_dst = Counter()

        self.udp_ports_dst = Counter()

        self.dns_queries = Counter()
        self.dns_query_types = Counter()
        self.dns_responses = []            
        self.dns_domain_ips = defaultdict(list)  

        self.http_requests = []
        self.http_responses = []

        self.tls_sni = Counter()
        self.tls_versions = Counter()
        self.tls_alpn = Counter()
        self.tls_ja3 = Counter()
        self.tls_connections = []          

        self.arp_requests = []             
        self.arp_replies = []              
        self.arp_gratuitous = []           
        self.ip_mac_history = defaultdict(list)  
        self.mac_to_ips = defaultdict(set)

        self.icmp_types = Counter()

        self.findings = []                 

    
    def load(self):
        if not os.path.exists(self.path):
            print(f"Error: file '{self.path}' not found.")
            sys.exit(1)
        print(f"[*] Reading file: {self.path} ...")
        self.packets = rdpcap(self.path)
        print(f"[*] Successfully read {len(self.packets)} packets.\n")

    
    def _record_arp_mac(self, ip, mac, ts, idx):
        hist = self.ip_mac_history[ip]
        self.mac_to_ips[mac].add(ip)
        if hist and hist[-1]["mac"] == mac:
            hist[-1]["last_seen"] = ts
            hist[-1]["count"] += 1
            if len(hist[-1]["evidence"]) < 10:
                hist[-1]["evidence"].append(idx)
        else:
            hist.append({
                "mac": mac, "first_seen": ts, "last_seen": ts,
                "count": 1, "evidence": [idx],
            })


    def analyze(self):
        for idx, pkt in enumerate(self.packets, start=1):
            self.total_packets += 1
            plen = len(pkt)
            self.total_bytes += plen
            ts = float(pkt.time)
            if self.start_time is None or ts < self.start_time:
                self.start_time = ts
            if self.end_time is None or ts > self.end_time:
                self.end_time = ts

           
            if pkt.haslayer(ARP):
                self.protocols["ARP"] += 1
                arp = pkt[ARP]
                if arp.op == 1:  
                    self.arp_requests.append((ts, idx, arp.pdst, arp.psrc))
                    if arp.psrc == arp.pdst:
                        self.arp_gratuitous.append((ts, idx, arp.psrc, arp.hwsrc))
                    else:
                        self._record_arp_mac(arp.psrc, arp.hwsrc, ts, idx)
                elif arp.op == 2:  
                    self.arp_replies.append((ts, idx, arp.psrc, arp.hwsrc))
                    self._record_arp_mac(arp.psrc, arp.hwsrc, ts, idx)
                    if arp.psrc == arp.pdst:
                        self.arp_gratuitous.append((ts, idx, arp.psrc, arp.hwsrc))

            ip_layer = None
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                self.protocols["IPv4"] += 1
            elif pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
                self.protocols["IPv6"] += 1

            if ip_layer is not None:
                src, dst = ip_layer.src, ip_layer.dst
                self.ip_src_pkts[src] += 1
                self.ip_dst_pkts[dst] += 1
                self.ip_src_bytes[src] += plen
                pair = tuple(sorted([src, dst]))
                self.conversations_pkts[pair] += 1
                self.conversations_bytes[pair] += plen

            
            if pkt.haslayer(TCP):
                self.protocols["TCP"] += 1
                tcp = pkt[TCP]
                paylen = len(tcp.payload) if tcp.payload else 0
                if ip_layer is not None:
                    self.tcp_ports_dst[tcp.dport] += 1
                    self.app_classes[classify_app("TCP", tcp.sport, tcp.dport)] += 1

                    endpoints = tuple(sorted([(ip_layer.src, tcp.sport), (ip_layer.dst, tcp.dport)]))
                    stream = self.tcp_streams.get(endpoints)
                    if stream is None:
                        stream = TCPStream(endpoints)
                        self.tcp_streams[endpoints] = stream
                    stream.update(ip_layer.src, tcp.sport, tcp.flags, int(tcp.seq),
                                  int(tcp.ack), paylen, ts, idx)

              
                if pkt.haslayer(Raw) and (tcp.dport == 80 or tcp.sport == 80):
                    self._parse_http(pkt, tcp, ip_layer, ts, idx)

           
                if pkt.haslayer(Raw) and (tcp.dport == 443 or tcp.sport == 443):
                    self._parse_tls(pkt, ip_layer, ts, idx)

    
            elif pkt.haslayer(UDP):
                self.protocols["UDP"] += 1
                udp = pkt[UDP]
                if ip_layer is not None:
                    self.udp_ports_dst[udp.dport] += 1
                    self.app_classes[classify_app("UDP", udp.sport, udp.dport)] += 1

                if pkt.haslayer(DNS):
                    self._parse_dns(pkt, ts, idx)


            elif pkt.haslayer(ICMP):
                self.protocols["ICMP"] += 1
                icmp = pkt[ICMP]
                name = ICMP_TYPES.get(int(icmp.type), f"Type {icmp.type}")
                self.icmp_types[name] += 1

        self._post_process()

    def _parse_http(self, pkt, tcp, ip_layer, ts, idx):
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        if payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")):
            lines = payload.split(b"\r\n")
            req_line = lines[0].decode(errors="ignore")
            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    headers[k.strip().lower().decode(errors="ignore")] = v.strip().decode(errors="ignore")
            self.http_requests.append({
                "idx": idx, "time": ts,
                "src": ip_layer.src if ip_layer else "?",
                "dst": ip_layer.dst if ip_layer else "?",
                "request": req_line,
                "host": headers.get("host", ""),
                "user_agent": headers.get("user-agent", ""),
                "referer": headers.get("referer", ""),
                "content_type": headers.get("content-type", ""),
                "content_length": headers.get("content-length", ""),
                "authorization": "PRESENT" if "authorization" in headers else "absent",
                "cookie": "PRESENT" if "cookie" in headers else "absent",
            })
        elif payload.startswith(b"HTTP/"):
            lines = payload.split(b"\r\n")
            status_line = lines[0].decode(errors="ignore")
            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    headers[k.strip().lower().decode(errors="ignore")] = v.strip().decode(errors="ignore")
            self.http_responses.append({
                "idx": idx, "time": ts,
                "src": ip_layer.src if ip_layer else "?",
                "dst": ip_layer.dst if ip_layer else "?",
                "status": status_line,
                "content_type": headers.get("content-type", ""),
                "content_length": headers.get("content-length", ""),
                "set_cookie": "PRESENT" if "set-cookie" in headers else "absent",
            })


    def _parse_tls(self, pkt, ip_layer, ts, idx):
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        info = parse_tls_record(payload)
        if not info:
            return
        if info["type"] == "ClientHello":
            self.tls_versions[tls_version_name(info["version"])] += 1
            if info["sni"]:
                self.tls_sni[info["sni"]] += 1
            for a in info["alpn"]:
                self.tls_alpn[a] += 1
            if info["ja3"]:
                self.tls_ja3[info["ja3"]] += 1
            self.tls_connections.append({
                "idx": idx, "time": ts,
                "src": ip_layer.src if ip_layer else "?",
                "dst": ip_layer.dst if ip_layer else "?",
                "sni": info["sni"], "alpn": info["alpn"],
                "ja3": info["ja3"], "version": tls_version_name(info["version"]),
            })
        elif info["type"] == "ServerHello":
            self.tls_versions[tls_version_name(info["version"]) + " (server)"] += 1


    def _parse_dns(self, pkt, ts, idx):
        dns = pkt[DNS]
        try:
            if dns.qr == 0 and dns.qdcount > 0:
                qname = dns[DNSQR].qname.decode(errors="ignore").rstrip(".")
                qtype = dns[DNSQR].qtype
                self.dns_queries[qname] += 1
                self.dns_query_types[qtype] += 1
            elif dns.qr == 1:
                qname = ""
                if dns.qdcount > 0 and dns.qd is not None:
                    qname = dns[DNSQR].qname.decode(errors="ignore").rstrip(".")
                rcode = dns.rcode
                answers = []
                if dns.ancount > 0 and dns.an is not None:
                    rr = dns.an
                    while rr is not None:
                        try:
                            rtype = rr.type
                            rdata = rr.rdata
                            ttl = rr.ttl
                            if rtype == 1:  # A
                                ip_str = rdata if isinstance(rdata, str) else str(rdata)
                                answers.append(("A", ip_str, ttl))
                                self.dns_domain_ips[qname].append((ip_str, ts, idx))
                            elif rtype == 28:  # AAAA
                                answers.append(("AAAA", str(rdata), ttl))
                            elif rtype == 5:  # CNAME
                                cn = rdata.decode(errors="ignore") if isinstance(rdata, bytes) else str(rdata)
                                answers.append(("CNAME", cn.rstrip("."), ttl))
                        except Exception:
                            pass
                        rr = rr.payload if hasattr(rr, "payload") and rr.payload and rr.payload.name == "DNS Resource Record" else None
                self.dns_responses.append({
                    "idx": idx, "time": ts, "domain": qname,
                    "rcode": rcode, "answers": answers,
                })
        except Exception:
            pass

  
    def _post_process(self):
        self._build_findings()


    def _add_finding(self, severity, title, what, why, evidence=None, first_seen=None,
                      last_seen=None, hosts=None):
        self.findings.append({
            "severity": severity, "title": title, "what": what, "why": why,
            "evidence": evidence or [], "first_seen": first_seen, "last_seen": last_seen,
            "hosts": hosts or [],
        })


    def _build_findings(self):

        conflicted_ips = {ip: hist for ip, hist in self.ip_mac_history.items() if len(hist) > 1}
        for ip, hist in conflicted_ips.items():
            macs = [h["mac"] for h in hist]
            all_evidence = []
            for h in hist:
                all_evidence.extend(h["evidence"])
            self._add_finding(
                "HIGH", f"ARP identity conflict on {ip}",
                what=f"IP {ip} was seen mapped to {len(set(macs))} different MAC addresses: {', '.join(dict.fromkeys(macs))}.",
                why="A single IP normally maps to one stable MAC address on a LAN. Multiple MACs for the same IP is the classic signature of ARP spoofing / a man-in-the-middle attempt (or a MAC/NIC change, DHCP re-lease, or VM migration).",
                evidence=sorted(set(all_evidence))[:10],
                first_seen=hist[0]["first_seen"], last_seen=hist[-1]["last_seen"],
                hosts=[ip],
            )

        shared_mac_ips = {mac: ips for mac, ips in self.mac_to_ips.items() if len(ips) > 1}
        for mac, ips in shared_mac_ips.items():
            ips_sorted = sorted(ips)
            self._add_finding(
                "CRITICAL" if len(ips) >= 2 and any(ip in conflicted_ips for ip in ips) else "MEDIUM",
                f"MAC address {mac} claimed by multiple IPs",
                what=f"MAC {mac} answered ARP for IPs: {', '.join(ips_sorted)}.",
                why="One network interface (MAC) legitimately claiming multiple IP addresses is unusual on a simple LAN and is consistent with an attacker impersonating both a victim and the gateway during an ARP MITM attack.",
                hosts=ips_sorted,
            )


        if conflicted_ips:
            gw_candidates = [ip for ip in conflicted_ips if ip.endswith(".1")]
            gateway_ip = gw_candidates[0] if gw_candidates else None
            victims = [ip for ip in conflicted_ips if ip != gateway_ip]
            if gateway_ip and victims:
                gw_macs = {h["mac"] for h in self.ip_mac_history[gateway_ip]}
                for v in victims:
                    v_macs = {h["mac"] for h in self.ip_mac_history[v]}
                    shared = gw_macs & v_macs
                    if shared:
                        mac = next(iter(shared))
                        self._add_finding(
                            "CRITICAL", "Possible MITM path reconstructed",
                            what=f"Attacker MAC {mac} is shared between gateway {gateway_ip} and host {v}, "
                                 f"consistent with the attacker inserting itself between victim and gateway.",
                            why="This is the textbook ARP-spoofing MITM pattern: attacker sends spoofed ARP "
                                "replies so both the victim and the gateway route traffic through the attacker's NIC.",
                            hosts=[v, gateway_ip, mac],
                        )

        if self.arp_gratuitous:
            idxs = [e[1] for e in self.arp_gratuitous][:10]
            self._add_finding(
                "MEDIUM" if len(self.arp_gratuitous) < 5 else "HIGH",
                "Gratuitous ARP observed",
                what=f"{len(self.arp_gratuitous)} gratuitous ARP packet(s) observed "
                     f"(IP announcing its own MAC unprompted).",
                why="Gratuitous ARP is normal after boot/DHCP/failover, but is also exactly how ARP-spoofing "
                    "tools broadcast forged mappings to poison the whole LAN's ARP caches at once.",
                evidence=idxs,
            )

        for stream in self.tcp_streams.values():
            if stream.retrans >= 5:
                total = stream.packets
                rate = stream.retrans / total * 100 if total else 0
                sev = "HIGH" if rate > 15 else "MEDIUM"
                self._add_finding(
                    sev, f"High retransmission rate: {stream.endpoints_str()}",
                    what=f"{stream.retrans} retransmissions out of {total} packets ({rate:.1f}%).",
                    why="High retransmission rates indicate packet loss, congestion, a struggling link, "
                        "or — in a security context — interference/interception on the path.",
                    evidence=stream.retrans_evidence,
                    first_seen=stream.first_seen, last_seen=stream.last_seen,
                    hosts=[stream.key[0][0], stream.key[1][0]],
                )
            if stream.rst >= 5:
                self._add_finding(
                    "MEDIUM", f"Multiple TCP resets: {stream.endpoints_str()}",
                    what=f"{stream.rst} RST packets observed on this stream.",
                    why="Frequent resets can indicate a firewall/IDS actively killing connections, "
                        "a service being unreachable, or a scan being rejected.",
                    evidence=[e[1] for e in stream.rst_events[:10]],
                    first_seen=stream.first_seen, last_seen=stream.last_seen,
                    hosts=[stream.key[0][0], stream.key[1][0]],
                )

        syn_targets = defaultdict(set)
        syn_counts = Counter()
        for stream in self.tcp_streams.values():
            if stream.syn >= 1 and stream.synack == 0:
                src_ip = stream.key[0][0]
                syn_targets[src_ip].add(stream.key[1][1])
                syn_counts[src_ip] += stream.syn

        port_scan_sources = set()
        for src, ports in syn_targets.items():
            if len(ports) >= 15:
                port_scan_sources.add(src)
                self._add_finding(
                    "HIGH", f"Possible port scan from {src}",
                    what=f"{src} sent SYN packets to {len(ports)} different destination ports "
                         f"with no completed handshake.",
                    why="Sequential/broad SYN attempts without full handshakes is the standard signature "
                        "of TCP port scanning (e.g. nmap -sS).",
                    hosts=[src],
                )
        for src, cnt in syn_counts.most_common(5):
            if cnt >= 100 and src not in port_scan_sources:
                self._add_finding(
                    "HIGH", f"High volume of unanswered SYNs from {src}",
                    what=f"{cnt} SYN packets from {src} without SYN/ACK.",
                    why="Could indicate a SYN flood attempt or an aggressive scan.",
                    hosts=[src],
                )

        incomplete_handshake_count = 0
        MAX_INCOMPLETE_FINDINGS = 5
        for stream in self.tcp_streams.values():
            src_ip = stream.key[0][0]
            if (stream.handshake_syn_seen and not stream.handshake_synack_seen
                    and stream.packets <= 3 and src_ip not in port_scan_sources):
                incomplete_handshake_count += 1
                if incomplete_handshake_count <= MAX_INCOMPLETE_FINDINGS:
                    self._add_finding(
                        "LOW", f"Incomplete handshake: {stream.endpoints_str()}",
                        what="SYN observed with no SYN/ACK reply captured.",
                        why="Could be a filtered/closed port, a one-sided capture, or scan activity.",
                        hosts=[stream.key[0][0], stream.key[1][0]],
                    )
        if incomplete_handshake_count > MAX_INCOMPLETE_FINDINGS:
            self._add_finding(
                "LOW", f"{incomplete_handshake_count - MAX_INCOMPLETE_FINDINGS} more incomplete handshakes not shown",
                what="Additional streams with SYN but no SYN/ACK were found beyond the ones listed above.",
                why="Grouped to keep the report readable; see the JSON export for the full list.",
            )


        for domain, entries in self.dns_domain_ips.items():
            distinct_ips = {ip for ip, _, _ in entries}
            if len(distinct_ips) >= 3:
                times = [t for _, t, _ in entries]
                span = max(times) - min(times)
                idxs = [i for _, _, i in entries][:10]
                sev = "MEDIUM" if span < 10 else "LOW"
                self._add_finding(
                    sev, f"DNS answer instability for {domain}",
                    what=f"{domain} resolved to {len(distinct_ips)} different IPs "
                         f"within {span:.1f}s: {', '.join(sorted(distinct_ips))}.",
                    why="Legitimate CDNs/load-balancers do this too, but rapid answer-flipping for the same "
                        "domain can also indicate DNS spoofing/poisoning or fast-flux infrastructure — worth a manual check.",
                    evidence=idxs,
                    hosts=[domain],
                )

        for req in self.http_requests:
            if req["authorization"] == "PRESENT":
                self._add_finding(
                    "HIGH", f"Authorization header sent in cleartext HTTP ({req['host'] or req['dst']})",
                    what="An HTTP (not HTTPS) request included an Authorization header.",
                    why="Credentials/tokens sent over unencrypted HTTP can be captured by anyone "
                        "on the network path, including a MITM attacker.",
                    evidence=[req["idx"]], first_seen=req["time"], hosts=[req["src"], req["dst"]],
                )

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))


    def ascii_timeline(self, buckets=30):
        if not self.packets:
            return "No data."
        timeline = Counter(int(float(p.time)) for p in self.packets)
        start = int(self.start_time)
        end = int(self.end_time)
        duration = max(end - start, 1)
        bucket_size = max(duration / buckets, 1)
        actual_buckets = min(buckets, int(duration / bucket_size) + 1)
        bucket_counts = [0] * (actual_buckets + 1)
        for t, cnt in timeline.items():
            idx = min(int((t - start) / bucket_size), actual_buckets)
            bucket_counts[idx] += cnt
        max_count = max(bucket_counts) if bucket_counts else 1
        lines = []
        for i, cnt in enumerate(bucket_counts):
            bar_len = int((cnt / max_count) * 40) if max_count else 0
            lines.append(f"  t+{int(i*bucket_size):>5}s | {'#' * bar_len} {cnt}")
        return "\n".join(lines)

    def build_report(self):
        L = []
        add = L.append
        n = self.top_n

        add("=" * 74)
        add(" PCAP ANALYSIS REPORT (PRO)")
        add("=" * 74)
        add(f"File: {self.path}")
        add(f"Total packets: {self.total_packets:,}")
        add(f"Total traffic volume: {human_bytes(self.total_bytes)}")
        if self.start_time and self.end_time:
            duration = self.end_time - self.start_time
            add(f"Time range: {fmt_time(self.start_time)}  to  {fmt_time(self.end_time)}")
            add(f"Total duration: {duration:.2f} seconds")
            if duration > 0:
                add(f"Average rate: {self.total_bytes/duration:.2f} B/s "
                    f"({self.total_packets/duration:.2f} pkt/s)")
        add("")


        add("=" * 74)
        add(" SECURITY FINDINGS (sorted by severity)")
        add("=" * 74)
        if not self.findings:
            add("  No findings.")
        for f in self.findings:
            add(f"[{f['severity']}] {f['title']}")
            add(f"    What:  {f['what']}")
            add(f"    Why:   {f['why']}")
            if f["hosts"]:
                add(f"    Hosts: {', '.join(str(h) for h in f['hosts'])}")
            if f["first_seen"]:
                rng = fmt_time_short(f["first_seen"])
                if f["last_seen"] and f["last_seen"] != f["first_seen"]:
                    rng += f" - {fmt_time_short(f['last_seen'])}"
                add(f"    When:  {rng}")
            if f["evidence"]:
                add(f"    Evidence packets: {', '.join('#' + str(e) for e in f['evidence'])}")
            add("")

        # ---- Protocol breakdown ----
        add("-" * 74)
        add(" Protocol breakdown")
        add("-" * 74)
        for proto, cnt in self.protocols.most_common():
            pct = (cnt / self.total_packets) * 100 if self.total_packets else 0
            add(f"  {proto:<10} {cnt:>8,} packets   ({pct:5.1f}%)")
        add("")

        add("-" * 74)
        add(" Traffic classification (protocol-aware)")
        add("-" * 74)
        for cls, cnt in self.app_classes.most_common():
            add(f"  {cls:<18} {cnt:>8,} packets")
        add("")


        add("-" * 74)
        add(f" Top talkers by bytes (Top {n})")
        add("-" * 74)
        for ip, b in self.ip_src_bytes.most_common(n):
            pct = (b / self.total_bytes) * 100 if self.total_bytes else 0
            add(f"  {ip:<20} {human_bytes(b):>12}   {pct:5.1f}% of total traffic")
        add("")

        add("-" * 74)
        add(f" Top talkers by packets — source (Top {n})")
        add("-" * 74)
        for ip, cnt in self.ip_src_pkts.most_common(n):
            add(f"  {ip:<20} {cnt:>8,} packets")
        add("")

        add("-" * 74)
        add(f" Top destination IPs (Top {n})")
        add("-" * 74)
        for ip, cnt in self.ip_dst_pkts.most_common(n):
            add(f"  {ip:<20} {cnt:>8,} packets")
        add("")

        add("-" * 74)
        add(f" Top conversations by volume (Top {n})")
        add("-" * 74)
        for pair, b in self.conversations_bytes.most_common(n):
            pkts = self.conversations_pkts[pair]
            add(f"  {pair[0]:<17} <-> {pair[1]:<17}  {human_bytes(b):>10}  ({pkts} packets)")
        add("")

        if self.tcp_ports_dst:
            add("-" * 74)
            add(f" Top TCP destination ports (Top {n})")
            add("-" * 74)
            for port, cnt in self.tcp_ports_dst.most_common(n):
                add(f"  Port {port:<6} {cnt:>8,} packets")
            add("")

        if self.udp_ports_dst:
            add("-" * 74)
            add(f" Top UDP destination ports (Top {n})")
            add("-" * 74)
            for port, cnt in self.udp_ports_dst.most_common(n):
                add(f"  Port {port:<6} {cnt:>8,} packets")
            add("")

        add("=" * 74)
        add(" ARP / MITM ANALYSIS")
        add("=" * 74)
        add(f"  ARP requests: {len(self.arp_requests)}   ARP replies: {len(self.arp_replies)}   "
            f"Gratuitous ARP: {len(self.arp_gratuitous)}")
        add("")
        add("  IP <-> MAC history table:")
        add("  " + "-" * 70)
        for ip, hist in sorted(self.ip_mac_history.items()):
            changes = len(hist) - 1
            for h in hist:
                add(f"  {ip:<16} {h['mac']:<18} first={fmt_time_short(h['first_seen'])}  "
                    f"last={fmt_time_short(h['last_seen'])}  seen={h['count']:<4} changes={changes}")
        add("")

        if self.arp_gratuitous:
            add("  Gratuitous ARP events:")
            for ts, idx, ip, mac in self.arp_gratuitous[:15]:
                add(f"    [{fmt_time_short(ts)}] #{idx}  {ip} announces itself at {mac}")
            add("")

        # ---- TCP flow summaries ----
        add("=" * 74)
        add(" TCP FLOW ANALYSIS")
        add("=" * 74)
        all_streams = list(self.tcp_streams.values())
        meaningful = [s for s in all_streams if s.bytes > 0 or s.packets > 3]
        trivial_count = len(all_streams) - len(meaningful)
        top_streams = sorted(meaningful, key=lambda s: s.bytes, reverse=True)[:n]
        if trivial_count:
            add(f"  ({trivial_count} single-packet/no-data streams omitted here — see Security Findings "
                f"for scan-related ones)")
            add("")
        for s in top_streams:
            add(f"  Conversation: {s.endpoints_str()}")
            add(f"    Packets: {s.packets}   Bytes: {human_bytes(s.bytes)}")
            add(f"    Handshake: {s.handshake_status()}")
            add(f"    SYN: {s.syn}  SYN-ACK: {s.synack}  FIN: {s.fin}  RST: {s.rst}")
            add(f"    Retransmissions: {s.retrans}   Duplicate ACKs: {s.dup_ack}   Out-of-order: {s.ooo}")
            if s.retrans / s.packets > 0.10 and s.packets > 10:
                add(f"    ⚠ High retransmission rate ({s.retrans/s.packets*100:.1f}%)")
            add("")

        if self.tls_connections:
            add("=" * 74)
            add(" TLS ANALYSIS")
            add("=" * 74)
            add("  TLS ClientHello versions seen:")
            for v, cnt in self.tls_versions.most_common():
                add(f"    {v:<20} {cnt}")
            add("")
            if self.tls_sni:
                add(f"  SNI (Top {n}):")
                for sni, cnt in self.tls_sni.most_common(n):
                    add(f"    {sni:<40} {cnt} connection(s)")
                add("")
            if self.tls_alpn:
                add("  ALPN protocols negotiated/offered:")
                for a, cnt in self.tls_alpn.most_common():
                    add(f"    {a:<15} {cnt}")
                add("")
            if self.tls_ja3:
                add(f"  JA3 client fingerprints (Top {n}):")
                for ja3, cnt in self.tls_ja3.most_common(n):
                    add(f"    {ja3}   ({cnt} connection(s))")
                add("")

        if self.dns_queries:
            add("=" * 74)
            add(" DNS ANALYSIS")
            add("=" * 74)
            add(f"  Total queries: {sum(self.dns_queries.values())}   "
                f"Total responses: {len(self.dns_responses)}")
            add("")
            add(f"  Queries (Top {n}):")
            for domain, cnt in self.dns_queries.most_common(n):
                add(f"    {domain:<40} {cnt} time(s)")
            add("")
            nx = [r for r in self.dns_responses if r["rcode"] == 3]
            if nx:
                add(f"  NXDOMAIN responses: {len(nx)}")
                for r in nx[:10]:
                    add(f"    [{fmt_time_short(r['time'])}] #{r['idx']}  {r['domain']} -> NXDOMAIN")
                add("")

        # ---- HTTP ----
        if self.http_requests:
            add("=" * 74)
            add(f" HTTP REQUESTS (first {min(len(self.http_requests), 20)})")
            add("=" * 74)
            for req in self.http_requests[:20]:
                add(f"  [{fmt_time_short(req['time'])}] #{req['idx']}  {req['src']} -> {req['dst']}")
                add(f"      {req['request']}")
                if req["host"]:
                    add(f"      Host: {req['host']}")
                if req["user_agent"]:
                    add(f"      User-Agent: {req['user_agent']}")
                if req["referer"]:
                    add(f"      Referer: {req['referer']}")
                if req["content_type"]:
                    add(f"      Content-Type: {req['content_type']}")
                add(f"      Authorization: {req['authorization']}   Cookie: {req['cookie']}")
            add("")

        if self.http_responses:
            add(f" HTTP RESPONSES (first {min(len(self.http_responses), 20)})")
            add("-" * 74)
            for resp in self.http_responses[:20]:
                add(f"  [{fmt_time_short(resp['time'])}] #{resp['idx']}  {resp['src']} -> {resp['dst']}  "
                    f"{resp['status']}")
            add("")

        # ---- ICMP ----
        if self.icmp_types:
            add("-" * 74)
            add(" ICMP breakdown")
            add("-" * 74)
            for name, cnt in self.icmp_types.most_common():
                add(f"  {name:<28} {cnt}")
            add("")

        # ---- Timeline ----
        add("-" * 74)
        add(" Traffic volume timeline")
        add("-" * 74)
        add(self.ascii_timeline())
        add("")

        add("=" * 74)
        add(" END OF REPORT")
        add("=" * 74)
        return "\n".join(L)

    def build_json(self):
        return {
            "file": self.path,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "protocols": dict(self.protocols),
            "app_classes": dict(self.app_classes),
            "top_talkers_bytes": self.ip_src_bytes.most_common(self.top_n),
            "top_talkers_packets": self.ip_src_pkts.most_common(self.top_n),
            "top_conversations": [
                {"pair": list(p), "bytes": b, "packets": self.conversations_pkts[p]}
                for p, b in self.conversations_bytes.most_common(self.top_n)
            ],
            "arp": {
                "requests": len(self.arp_requests),
                "replies": len(self.arp_replies),
                "gratuitous": len(self.arp_gratuitous),
                "ip_mac_history": {
                    ip: [{"mac": h["mac"], "first_seen": h["first_seen"], "last_seen": h["last_seen"],
                          "count": h["count"], "evidence": h["evidence"]} for h in hist]
                    for ip, hist in self.ip_mac_history.items()
                },
            },
            "tcp_streams": [
                {
                    "endpoints": s.endpoints_str(), "packets": s.packets, "bytes": s.bytes,
                    "syn": s.syn, "synack": s.synack, "fin": s.fin, "rst": s.rst,
                    "retransmissions": s.retrans, "duplicate_acks": s.dup_ack,
                    "out_of_order": s.ooo, "handshake": s.handshake_status(),
                } for s in self.tcp_streams.values()
            ],
            "tls_connections": self.tls_connections,
            "dns_queries": self.dns_queries.most_common(self.top_n),
            "http_requests": self.http_requests[:50],
            "icmp_types": dict(self.icmp_types),
            "findings": self.findings,
        }


def main():
    parser = argparse.ArgumentParser(description="Forensic-grade pcap/pcapng traffic analyzer")
    parser.add_argument("pcap_file", help="Path to the pcap or pcapng file")
    parser.add_argument("--top", type=int, default=15, help="Number of top items per section (default: 15)")
    parser.add_argument("--out", help="Save the text report to this path")
    parser.add_argument("--json", help="Save the report as JSON to this path")
    args = parser.parse_args()

    analyzer = PcapAnalyzer(args.pcap_file, top_n=args.top)
    analyzer.load()
    analyzer.analyze()
    report = analyzer.build_report()
    print(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[OK] Text report saved to '{args.out}'.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(analyzer.build_json(), f, ensure_ascii=False, indent=2, default=str)
        print(f"[OK] JSON report saved to '{args.json}'.")


if __name__ == "__main__":
    main()
