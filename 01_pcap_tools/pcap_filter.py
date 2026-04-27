#!/usr/bin/env python3
"""
pcap_filter.py

Usage:
  pcap_filter.py [-g|--no-gzip] <origin> <destination> <ip_file> [-p <ports>]

- origin: a .pcap / .pcap.gz / .pcap.xz file or a directory containing such files
- destination: output directory for filtered files
- ip_file: file containing one source IP per line (comments starting with # are ignored)
- -p / --ports: optional comma-separated list of source ports to filter (e.g., 80,443,53)
- -g / --no-gzip: if set, output will be plain .pcap; otherwise, output will be compressed .pcap.gz

Filtering logic per packet:
  Remove packet if:
    - The packet's source IP is in the IP list AND
      ( (the packet is TCP and its tcp.srcport is in the port list) OR
        (the packet is UDP and its udp.srcport is in the port list) OR
        (the packet is neither TCP nor UDP) )

Packets not matching the above removal condition are written to output.

"""

from __future__ import annotations
import argparse
import gzip
import os
import shutil
import subprocess
import lzma
import tempfile
from typing import List


def load_list_from_file(path: str) -> List[str]:
    items: List[str] = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            items.append(line)
    return items


def build_display_filter(ips: List[str], ports: List[str]) -> str:
    """Build the tshark display filter based on the filtering logic.

    Removal condition (before negation):
      (ip.src in IP_LIST) AND (TCP+port match OR UDP+port match OR non-TCP/UDP)

    Final display filter is: not (REMOVAL_CONDITION)
    """
    if not ips:
        raise ValueError("IP list is empty")

    # (ip.src == IP1) || (ip.src == IP2) ...
    ip_expr = ' || '.join(f'(ip.src == {ip})' for ip in ips)

    # Non-TCP/UDP part:
    non_tcp_udp = f'({ip_expr} && (not tcp) && (not udp))'

    # TCP / UDP parts
    if ports:
        for p in ports:
            if not p.isdigit():
                raise ValueError(f"Invalid port: {p}")
        tcp_ports = ' || '.join(f'(tcp.srcport == {p})' for p in ports)
        udp_ports = ' || '.join(f'(udp.srcport == {p})' for p in ports)
        tcp_part = f'({ip_expr} && tcp && ({tcp_ports}))'
        udp_part = f'({ip_expr} && udp && ({udp_ports}))'
    else:
        # If no ports provided: any TCP/UDP with matching IP should be removed
        tcp_part = f'({ip_expr} && tcp)'
        udp_part = f'({ip_expr} && udp)'

    removal = ' || '.join([non_tcp_udp, tcp_part, udp_part])
    display_filter = f'not ({removal})'
    return display_filter


def is_pcap_file(name: str) -> bool:
    return name.endswith('.pcap') or name.endswith('.pcap.gz') or name.endswith('.pcap.xz')


def gather_input_files(origin: str) -> List[str]:
    if os.path.isdir(origin):
        return [os.path.join(origin, f) for f in sorted(os.listdir(origin)) if is_pcap_file(f)]
    if os.path.isfile(origin) and is_pcap_file(origin):
        return [origin]
    raise ValueError("Origin must be a pcap/pcap.gz/pcap.xz file or a directory containing them")


def parse_ports(s: str) -> List[str]:
    if not s:
        return []
    return [p.strip() for p in s.split(',') if p.strip()]


def process_file(path: str, out_dir: str, ips: List[str], ports: List[str], no_gzip: bool) -> None:
    base = os.path.basename(path)
    if base.endswith('.pcap.gz'):
        stem = base[:-8]
    elif base.endswith('.pcap.xz'):
        stem = base[:-8]
    elif base.endswith('.pcap'):
        stem = base[:-5]
    else:
        stem = base

    out_name = f"{stem}-filtered.pcap"
    os.makedirs(out_dir, exist_ok=True)

    # Prepare input (decompress if needed)
    tmp_input = None
    if path.endswith('.pcap.gz'):
        fd, tmp_input = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        with gzip.open(path, 'rb') as fin, open(tmp_input, 'wb') as fout:
            shutil.copyfileobj(fin, fout)
        input_path = tmp_input
    elif path.endswith('.pcap.xz'):
        fd, tmp_input = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        with lzma.open(path, 'rb') as fin, open(tmp_input, 'wb') as fout:
            shutil.copyfileobj(fin, fout)
        input_path = tmp_input
    else:
        input_path = path

    fd2, tmp_output = tempfile.mkstemp(suffix='.pcap')
    os.close(fd2)

    display_filter = build_display_filter(ips, ports)
    cmd = ['tshark', '-r', input_path, '-Y', display_filter, '-w', tmp_output]
    subprocess.run(cmd, check=True)

    if no_gzip:
        final_path = os.path.join(out_dir, out_name)
        shutil.move(tmp_output, final_path)
    else:
        final_path = os.path.join(out_dir, out_name + '.gz')
        with open(tmp_output, 'rb') as fin, gzip.open(final_path, 'wb') as fout:
            shutil.copyfileobj(fin, fout)
        os.remove(tmp_output)

    print(f"Wrote: {final_path}")

    if tmp_input and os.path.exists(tmp_input):
        os.remove(tmp_input)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Filter pcap/pcap.gz/pcap.xz files based on source IP and optional source ports")
    parser.add_argument('-g', '--no-gzip', action='store_true', help='Do not compress output (produce .pcap). Default: compress as .pcap.gz')
    parser.add_argument('origin', help='Input pcap/pcap.gz file or directory')
    parser.add_argument('destination', help='Output directory')
    parser.add_argument('ip_file', help='File containing source IPs, one per line')
    parser.add_argument('-p', '--ports', help='Comma-separated list of source ports')
    args = parser.parse_args()

    ips = load_list_from_file(args.ip_file)
    ports = parse_ports(args.ports)

    files = gather_input_files(args.origin)
    for f in files:
        process_file(f, args.destination, ips, ports, args.no_gzip)
