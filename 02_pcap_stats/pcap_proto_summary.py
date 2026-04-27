#!/usr/bin/env python3
"""
Count TCP, UDP, ICMP, and total packets in PCAP files.

Features:
- Reads all .pcap files from an input directory.
- Excludes specific files based on a configurable list.
- Computes TCP, UDP, ICMP, total packets, and the remainder.
- Prints per-file summary and a global summary.
- Uses Scapy's PcapReader for efficiency.

Usage:
    python3 count_protocols.py /path/to/pcap_directory
"""

import os
import sys
import lzma
import tempfile
from scapy.all import PcapReader, TCP, UDP, ICMP


# List of PCAP filenames to skip (exact matches)
EXCLUDE_FILES = [
    # Example:
    # "2025-01-10.pcap",
    # "bad_day.pcap",
    "darknet_20251009.pcap",
]


def decompress_if_needed(path):
    """
    Return (usable_path, temp_path)
    usable_path = path to use
    temp_path = temporary file to delete later (or None if no temp was created)
    """
    if path.endswith(".pcap"):
        return path, None

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp.name
    tmp.close()

    if path.endswith(".pcap.gz"):
        opener = gzip.open
    elif path.endswith(".pcap.xz"):
        opener = lzma.open
    else:
        raise ValueError(f"Unsupported format: {path}")

    with opener(path, "rb") as comp, open(tmp_path, "wb") as out:
        out.write(comp.read())

    return tmp_path, tmp_path


def count_packets(filename):
    """
    Count TCP, UDP, ICMP, and total packets inside a PCAP file.

    Returns:
        (tcp_count, udp_count, icmp_count, total_count, remainder)
    """
    tcp = udp = icmp = total = 0

    try:
        usable, temp = decompress_if_needed(filename)

        with PcapReader(usable) as pcap:
            for pkt in pcap:
                total += 1

                if TCP in pkt:
                    tcp += 1
                elif UDP in pkt:
                    udp += 1
                elif ICMP in pkt:
                    icmp += 1

    except Exception as e:
        print(f"⚠️ Error processing {filename}: {e}")

    finally:
        if "temp" in locals() and temp:
            try:
                os.remove(temp)
            except:
                pass

    remainder = total - (tcp + udp + icmp)
    return tcp, udp, icmp, total, remainder


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 count_protocols.py <pcap_directory>")
        sys.exit(1)

    pcap_dir = sys.argv[1]

    if not os.path.isdir(pcap_dir):
        print(f"Error: '{pcap_dir}' is not a directory.")
        sys.exit(1)

    print("Input directory:", pcap_dir)
    print("Excluded files:", EXCLUDE_FILES)
    print()

    results = []

    for fname in sorted(os.listdir(pcap_dir)):
        if not fname.endswith(".pcap"):
            continue
        if fname in EXCLUDE_FILES:
            print("Skipping (excluded):", fname)
            continue

        full_path = os.path.join(pcap_dir, fname)
        print("Processing:", fname)

        tcp, udp, icmp, total, remainder = count_packets(full_path)

        results.append({
            "file": fname,
            "tcp": tcp,
            "udp": udp,
            "icmp": icmp,
            "remainder": remainder,
            "total": total
        })

    print("\n=== SUMMARY PER FILE ===")
    for r in results:
        print(f"{r['file']}: "
              f"TCP={r['tcp']} UDP={r['udp']} ICMP={r['icmp']} "
              f"Remainder={r['remainder']} Total={r['total']}")

    print("\n=== GLOBAL TOTAL ===")
    sum_tcp = sum(r["tcp"] for r in results)
    sum_udp = sum(r["udp"] for r in results)
    sum_icmp = sum(r["icmp"] for r in results)
    sum_total = sum(r["total"] for r in results)
    sum_remainder = sum_total - (sum_tcp + sum_udp + sum_icmp)

    print(f"TOTAL: TCP={sum_tcp}  UDP={sum_udp}  ICMP={sum_icmp}  "
          f"Remainder={sum_remainder}  Total={sum_total}")

    if sum_total > 0:
        pct_tcp = (sum_tcp / sum_total) * 100
        pct_udp = (sum_udp / sum_total) * 100
        pct_icmp = (sum_icmp / sum_total) * 100
        pct_remainder = (sum_remainder / sum_total) * 100
        print(f"PERCENTAGE: TCP={pct_tcp:.2f}%  UDP={pct_udp:.2f}%  ICMP={pct_icmp:.2f}%  Remainder={pct_remainder:.2f}%")


if __name__ == "__main__":
    main()
