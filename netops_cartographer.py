#!/usr/bin/env python3
"""
NetOps Cartographer

Advanced single-file networking showcase:
- Async multi-target TCP scanning with bounded concurrency
- Service fingerprinting (HTTP banners, SSH greeting, SMTP greeting)
- TLS certificate extraction (subject, issuer, validity window)
- CIDR expansion and host list support
- Risk scoring and JSON report export

Examples:
  python netops_cartographer.py --targets 192.168.1.0/30 --ports 22,80,443
  python netops_cartographer.py --targets scan_targets.txt --top-ports --json report.json
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
import re

TOP_PORTS: Tuple[int, ...] = (
    21, 22, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 1723, 1883, 2049, 2375, 3000,
    3306, 3389, 5000, 5432, 5672, 5900, 6379, 6443, 7001, 8080, 8443,
    9000, 9092, 9200, 11211, 27017,
)

HTTP_PORTS: Set[int] = {80, 8080, 8000, 8888, 3000, 5000, 7001, 9000}
TLS_HINT_PORTS: Set[int] = {443, 465, 636, 993, 995, 8443}
BANNER_PORTS: Set[int] = {22, 25, 110, 143, 587}


@dataclasses.dataclass
class TlsInfo:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    san_count: int


@dataclasses.dataclass
class PortFinding:
    port: int
    state: str
    latency_ms: float
    service_hint: str
    banner: Optional[str] = None
    tls: Optional[TlsInfo] = None


@dataclasses.dataclass
class HostReport:
    host: str
    findings: List[PortFinding]
    score: int
    notes: List[str]
    reverse_dns: List[str]
    asn_org: Optional[str]
    asn_number: Optional[str]


class ScanError(Exception):
    pass


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_ports(port_text: str) -> List[int]:
    ports: Set[int] = set()
    for token in port_text.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(token)
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        raise ScanError("No valid ports parsed")
    return sorted(ports)


def iter_targets(raw_targets: Sequence[str]) -> List[str]:
    out: Set[str] = set()
    for raw in raw_targets:
        raw = raw.strip()
        if not raw:
            continue
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            for ip in net.hosts():
                out.add(str(ip))
        else:
            out.add(raw)
    return sorted(out)


def load_targets_arg(targets_arg: str) -> List[str]:
    # If path exists, treat as file with one target per line.
    try:
        with open(targets_arg, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f.readlines()]
        expanded = iter_targets(lines)
        if expanded:
            return expanded
    except OSError:
        pass

    # Fallback: comma-separated inline targets.
    return iter_targets([x.strip() for x in targets_arg.split(",")])


async def try_connect(host: str, port: int, timeout: float) -> Tuple[bool, float, Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        latency = (time.perf_counter() - t0) * 1000.0
        return True, latency, reader, writer
    except Exception:
        latency = (time.perf_counter() - t0) * 1000.0
        return False, latency, None, None


async def grab_http_head(host: str, port: int, timeout: float) -> Optional[str]:
    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", "ignore")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        text = data.decode("utf-8", "replace").splitlines()
        return text[0].strip() if text else None
    except Exception:
        return None


async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

        if port in (25, 587):
            writer.write(b"EHLO probe.local\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", "replace").strip().replace("\r", " ").replace("\n", " ")
        return banner[:220] if banner else None
    except Exception:
        return None


def parse_name_tuple(name_tuple: Tuple[Tuple[str, str], ...]) -> str:
    parts = []
    for pair in name_tuple:
        for k, v in pair:
            if k == "commonName":
                parts.append(v)
    return ", ".join(parts) if parts else "n/a"


def _tls_probe_blocking(host: str, port: int, timeout: float) -> Optional[TlsInfo]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()

    if not cert:
        return None

    subject = parse_name_tuple(cert.get("subject", ()))
    issuer = parse_name_tuple(cert.get("issuer", ()))
    sans = cert.get("subjectAltName", ())

    return TlsInfo(
        subject=subject,
        issuer=issuer,
        not_before=cert.get("notBefore", "n/a"),
        not_after=cert.get("notAfter", "n/a"),
        san_count=len(sans),
    )


async def tls_probe(host: str, port: int, timeout: float) -> Optional[TlsInfo]:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_tls_probe_blocking, host, port, timeout), timeout=timeout + 0.8)
    except Exception:
        return None


async def scan_one_port(host: str, port: int, timeout: float) -> PortFinding:
    is_open, latency, reader, writer = await try_connect(host, port, timeout)

    if not is_open:
        return PortFinding(port=port, state="closed", latency_ms=latency, service_hint="unknown")

    if writer is not None:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    hint = "tcp"
    banner = None
    tls = None

    if port in HTTP_PORTS:
        hint = "http"
        banner = await grab_http_head(host, port, timeout)
    elif port in BANNER_PORTS:
        hint = "banner"
        banner = await grab_banner(host, port, timeout)

    if port in TLS_HINT_PORTS:
        hint = "tls"
        tls = await tls_probe(host, port, timeout)
        if tls is None:
            # Some services run plaintext on nonstandard ports despite hints.
            maybe = await grab_banner(host, port, timeout)
            if maybe:
                banner = maybe
                hint = "banner"

    return PortFinding(
        port=port,
        state="open",
        latency_ms=latency,
        service_hint=hint,
        banner=banner,
        tls=tls,
    )


async def scan_host(host: str, ports: Sequence[int], timeout: float, sem: asyncio.Semaphore) -> HostReport:
    findings: List[PortFinding] = []

    async def bounded_scan(p: int) -> PortFinding:
        async with sem:
            return await scan_one_port(host, p, timeout)

    tasks = [asyncio.create_task(bounded_scan(p)) for p in ports]
    for coro in asyncio.as_completed(tasks):
        findings.append(await coro)

    findings.sort(key=lambda x: x.port)
    score, notes = score_host(findings)
    reverse_dns = await reverse_dns_lookup(host)
    asn_number, asn_org = await asn_lookup(host, timeout)
    if reverse_dns:
        notes.append("Reverse DNS: " + ", ".join(reverse_dns[:3]))
    if asn_number and asn_org:
        notes.append(f"ASN: {asn_number} ({asn_org})")
    return HostReport(
        host=host,
        findings=findings,
        score=score,
        notes=notes,
        reverse_dns=reverse_dns,
        asn_org=asn_org,
        asn_number=asn_number,
    )


async def reverse_dns_lookup(host: str) -> List[str]:
    if not is_ip_literal(host):
        return []
    try:
        _, aliases, _ = await asyncio.to_thread(socket.gethostbyaddr, host)
        names = [a.strip() for a in aliases if a.strip()]
        return sorted(set(names))
    except Exception:
        return []


def _asn_lookup_blocking(host: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    if not is_ip_literal(host):
        return None, None

    query = f" -v {host}\r\n".encode("ascii", "ignore")
    with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as s:
        s.sendall(query)
        s.shutdown(socket.SHUT_WR)
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk

    text = raw.decode("utf-8", "replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None, None

    # Format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    parts = [p.strip() for p in lines[1].split("|")]
    if len(parts) < 7:
        return None, None
    asn = parts[0]
    org = parts[6]
    return asn or None, org or None


async def asn_lookup(host: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_asn_lookup_blocking, host, timeout), timeout=timeout + 1.2)
    except Exception:
        return None, None


def score_host(findings: Sequence[PortFinding]) -> Tuple[int, List[str]]:
    score = 0
    notes: List[str] = []

    open_ports = [f for f in findings if f.state == "open"]
    score += min(25, len(open_ports) * 2)

    sensitive_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 9200, 27017}
    exposure = [f.port for f in open_ports if f.port in sensitive_ports]
    score += min(30, len(exposure) * 4)
    if exposure:
        notes.append("Sensitive ports exposed: " + ", ".join(map(str, sorted(exposure))))

    insecure_banner_hits = 0
    for f in open_ports:
        if f.banner:
            b = f.banner.lower()
            if "server:" in b and ("apache/2.2" in b or "iis/6" in b or "nginx/1.0" in b):
                insecure_banner_hits += 1
            if "openssh_5" in b or "dropbear" in b:
                insecure_banner_hits += 1
    score += min(20, insecure_banner_hits * 5)
    if insecure_banner_hits:
        notes.append("Potentially outdated service banners detected")

    tls_issues = 0
    now = datetime.now(timezone.utc)
    for f in open_ports:
        if f.tls:
            try:
                na = datetime.strptime(f.tls.not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (na - now).days
                if days_left < 21:
                    tls_issues += 1
            except Exception:
                tls_issues += 1
    score += min(15, tls_issues * 5)
    if tls_issues:
        notes.append("TLS certificate expiry/parse issues found")

    if score < 20:
        notes.append("Low external attack surface observed")

    return min(100, score), notes


def format_host_report(rep: HostReport) -> str:
    lines = []
    lines.append(f"\n[{rep.host}] risk={rep.score}/100")
    if rep.reverse_dns:
        lines.append("  rdns: " + ", ".join(rep.reverse_dns[:3]))
    if rep.asn_number and rep.asn_org:
        lines.append(f"  asn : AS{rep.asn_number} {rep.asn_org}")
    if rep.notes:
        for n in rep.notes:
            lines.append(f"  - {n}")

    open_findings = [f for f in rep.findings if f.state == "open"]
    if not open_findings:
        lines.append("  No open scanned ports")
        return "\n".join(lines)

    lines.append("  Open ports:")
    for f in open_findings:
        base = f"    {f.port:5d}  {f.service_hint:<6}  {f.latency_ms:8.2f} ms"
        if f.banner:
            base += f"  | banner: {f.banner}"
        if f.tls:
            base += f"  | tls-cn: {f.tls.subject} | expires: {f.tls.not_after}"
        lines.append(base)
    return "\n".join(lines)


def to_json_ready(reports: Sequence[HostReport], ports: Sequence[int], elapsed_s: float) -> Dict[str, object]:
    return {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "elapsed_seconds": round(elapsed_s, 3),
            "ports_scanned": list(ports),
        },
        "hosts": [
            {
                "host": rep.host,
                "score": rep.score,
                "notes": rep.notes,
                "reverse_dns": rep.reverse_dns,
                "asn_number": rep.asn_number,
                "asn_org": rep.asn_org,
                "findings": [
                    {
                        "port": f.port,
                        "state": f.state,
                        "latency_ms": round(f.latency_ms, 3),
                        "service_hint": f.service_hint,
                        "banner": f.banner,
                        "tls": dataclasses.asdict(f.tls) if f.tls else None,
                    }
                    for f in rep.findings
                ],
            }
            for rep in reports
        ],
    }


def classify_service(f: PortFinding) -> str:
    if f.tls is not None:
        return "tls"
    if f.service_hint == "http":
        return "http"
    if f.service_hint == "banner" and f.banner:
        b = f.banner.lower()
        if "ssh" in b:
            return "ssh"
        if "smtp" in b or b.startswith("220"):
            return "smtp"
        if "imap" in b:
            return "imap"
        if "pop" in b:
            return "pop"
    return "tcp"


def extract_passive_domains(rep: HostReport) -> List[str]:
    # Passive extraction from TLS CN and banner text. No additional probes.
    domains: Set[str] = set()
    host_like = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    for f in rep.findings:
        if f.tls and f.tls.subject and f.tls.subject != "n/a":
            for m in host_like.findall(f.tls.subject):
                domains.add(m.lower())
        if f.banner:
            for m in host_like.findall(f.banner):
                domains.add(m.lower())
    return sorted(domains)


def build_graph(reports: Sequence[HostReport]) -> Dict[str, object]:
    nodes: List[Dict[str, str]] = []
    edges: List[Dict[str, str]] = []

    seen_nodes: Set[str] = set()

    def add_node(node_id: str, node_type: str, label: str) -> None:
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "label": label})

    for rep in reports:
        host_id = f"host:{rep.host}"
        add_node(host_id, "host", rep.host)

        for rd in rep.reverse_dns:
            rd_id = f"dns:{rd}"
            add_node(rd_id, "dns", rd)
            edges.append({"src": host_id, "dst": rd_id, "rel": "reverse_dns"})

        if rep.asn_number and rep.asn_org:
            asn_id = f"asn:{rep.asn_number}"
            add_node(asn_id, "asn", f"AS{rep.asn_number} {rep.asn_org}")
            edges.append({"src": host_id, "dst": asn_id, "rel": "origin_asn"})

        for f in rep.findings:
            if f.state != "open":
                continue
            svc = classify_service(f)
            svc_id = f"svc:{svc}:{f.port}"
            add_node(svc_id, "service", f"{svc}/{f.port}")
            edges.append({"src": host_id, "dst": svc_id, "rel": "exposes"})

        for d in extract_passive_domains(rep):
            d_id = f"domain:{d}"
            add_node(d_id, "domain", d)
            edges.append({"src": host_id, "dst": d_id, "rel": "mentions"})

    return {"nodes": nodes, "edges": edges}


def graph_to_dot(graph: Dict[str, object]) -> str:
    nodes = graph["nodes"]
    edges = graph["edges"]
    lines = ["digraph netops {", "  rankdir=LR;", "  graph [fontname=Helvetica];", "  node [shape=box style=rounded fontname=Helvetica];"]
    for n in nodes:
        nid = str(n["id"]).replace('"', "")
        label = str(n["label"]).replace('"', "")
        ntype = str(n["type"])
        color = {
            "host": "#6baed6",
            "service": "#9ecae1",
            "asn": "#fdae6b",
            "dns": "#74c476",
            "domain": "#bcbddc",
        }.get(ntype, "#cccccc")
        lines.append(f'  "{nid}" [label="{label}" fillcolor="{color}" style="filled,rounded"];')
    for e in edges:
        src = str(e["src"]).replace('"', "")
        dst = str(e["dst"]).replace('"', "")
        rel = str(e["rel"]).replace('"', "")
        lines.append(f'  "{src}" -> "{dst}" [label="{rel}"];')
    lines.append("}")
    return "\n".join(lines)


async def run_scan(args: argparse.Namespace) -> int:
    ports = list(TOP_PORTS) if args.top_ports else parse_ports(args.ports)
    targets = load_targets_arg(args.targets)
    if not targets:
        raise ScanError("No targets resolved from --targets")

    print("NetOps Cartographer")
    print(f"Targets        : {len(targets)}")
    print(f"Ports/target   : {len(ports)}")
    print(f"Concurrency    : {args.concurrency}")
    print(f"Timeout        : {args.timeout}s")

    sem = asyncio.Semaphore(args.concurrency)
    started = time.perf_counter()

    tasks = [asyncio.create_task(scan_host(h, ports, args.timeout, sem)) for h in targets]
    reports: List[HostReport] = []
    for t in asyncio.as_completed(tasks):
        rep = await t
        reports.append(rep)
        print(format_host_report(rep))

    reports.sort(key=lambda x: x.host)
    elapsed = time.perf_counter() - started
    graph = build_graph(reports)

    print("\n--- Summary ---")
    risky = sorted(reports, key=lambda r: r.score, reverse=True)
    for rep in risky[: min(5, len(risky))]:
        print(f"{rep.host:20} score={rep.score:3d} open={sum(1 for f in rep.findings if f.state == 'open')}")
    print(f"Elapsed: {elapsed:.2f}s")

    if args.json:
        payload = to_json_ready(reports, ports, elapsed)
        payload["graph"] = graph
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"JSON report written: {args.json}")

    if args.graph_dot:
        dot = graph_to_dot(graph)
        with open(args.graph_dot, "w", encoding="utf-8") as f:
            f.write(dot)
        print(f"Graph DOT written: {args.graph_dot}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Async network cartographer + service intelligence")
    p.add_argument(
        "--targets",
        required=True,
        help="CIDR, comma-separated hosts, or path to file with one target per line",
    )
    p.add_argument(
        "--ports",
        default="22,80,443,3389,5432,6379,8080",
        help="Ports list/ranges (e.g. 22,80,443,8000-8100)",
    )
    p.add_argument("--top-ports", action="store_true", help="Scan curated top port set")
    p.add_argument("--concurrency", type=int, default=300, help="Max concurrent socket tasks")
    p.add_argument("--timeout", type=float, default=1.2, help="Connect/read timeout seconds")
    p.add_argument("--json", help="Write full JSON report to file")
    p.add_argument("--graph-dot", help="Write relationship graph in Graphviz DOT format")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")

    try:
        return asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("Interrupted")
        return 130
    except ScanError as e:
        print(f"Error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
