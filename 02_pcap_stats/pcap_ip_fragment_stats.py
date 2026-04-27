#!/usr/bin/env python3
import os
import sys
import subprocess
import gzip
import tempfile

"""
This file processes pcap files in a given directory (including .pcap.gz files),
extracting IP fragmentation statistics using tshark.
It prints the total number of packets, number of fragmented packets,
and counts of first and non-first fragments for each pcap file.

Usage:
    python pcap_ip_fragment_stats.py <directory>

Requirements:
    - Python 3.6+
    - tshark (part of Wireshark) installed and in PATH

Example:
    python pcap_ip_fragment_stats.py ./pcaps/
"""

def get_fragment_stats(pcap_path):
    """
    Returns a dictionary with fragmentation statistics from a pcap file.
    Fields returned:
      total, fragmented, first_frag, nonfirst_frag
    using tshark.
    """
    # tshark -r file -T fields -e ip.flags.mf -e ip.frag_offset
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.flags.mf",
        "-e", "ip.frag_offset"
    ]

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return None  # Error processing pcap file

    total = 0
    fragmented = 0
    first_frag = 0
    nonfirst_frag = 0

    for line in output.splitlines():
        total += 1
        mf, offset = (line.split('\t') + ["", ""])[:2]
        mf = mf.strip()
        offset = offset.strip()

        if mf == "" and offset == "":
            continue  # No is a IP packet / fragmented packet

        offset_val = int(offset) if offset.isdigit() else 0

        # Fragmented packet if ip.flags.mf==1 or ip.frag_offset > 0
        if mf == "1" or offset_val > 0:
            fragmented += 1
            if offset_val == 0:
                first_frag += 1
            else:
                nonfirst_frag += 1

    return {
        "total": total,
        "fragmented": fragmented,
        "first_frag": first_frag,
        "nonfirst_frag": nonfirst_frag
    }


def print_stats(fname, stats):
    if not stats:
        print("Error processing pcap file")
        return

    print(f"{fname}:", end='\t')
    print(f"Total packets: {stats['total']}", end='\t')
    print(f"Fragmented packets: {stats['fragmented']}", end='\t')
    print(f"  First fragments: {stats['first_frag']}", end='\t')
    print(f"  Non-first fragments: {stats['nonfirst_frag']}")


def process_directory(directory):
    for root, _, files in os.walk(directory):
        for fname in sorted(files):
            full_path = os.path.join(root, fname)

            # Case 1: .pcap.gz file -> decompress temporarily
            if fname.endswith(".pcap.gz"):
                with gzip.open(full_path, "rb") as f_in:
                    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                        tmp.write(f_in.read())
                        tmp_path = tmp.name

                stats = get_fragment_stats(tmp_path)
                print_stats(fname, stats)

                os.unlink(tmp_path)  # Remove temporary file

            # Case 2: normal .pcap file -> process directly
            elif fname.endswith(".pcap"):
                stats = get_fragment_stats(full_path)
                print_stats(fname, stats)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        sys.exit(1)

    process_directory(directory)
