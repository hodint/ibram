#!/usr/bin/env python3
"""
merge_pcap_days.py
------------------

Merge multiple pcap/pcap.gz/pcap.xz files that share the same final date
in their filename (e.g. *_20251103.pcap) into one file per date.

Usage:
    python merge_pcap_days.py <input_dir> <output_dir> <mask> [-g|--no-gzip]

Example:
    python merge_pcap_days.py ./input ./merged darknet
    python merge_pcap_days.py ./input ./merged darknet --no-gzip

By default, output files are compressed as .pcap.gz unless --no-gzip is used.

Requirements:
    - Python 3.10+
    - mergecap (Wireshark CLI)
    - xz (for handling .pcap.xz)
"""

import os
import re
import sys
import glob
import subprocess
import gzip
import shutil
import argparse
import tempfile
from pathlib import Path


def abort(msg):
    print(f"❌  ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def ensure_tool(cmd_name):
    """
    Ensure a required tool is available in PATH.
    """
    try:
        subprocess.run([cmd_name, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        abort(f"'{cmd_name}' not found. Please install it or add it to PATH.")


def list_pcaps(input_dir):
    """
    List .pcap, .pcap.gz, and .pcap.xz files sorted alphabetically.
    """
    exts = ("*.pcap", "*.pcap.gz", "*.pcap.xz")
    files = []
    for e in exts:
        files += glob.glob(os.path.join(input_dir, e))
    files = sorted(files)
    if not files:
        abort("No PCAP files found in input directory.")
    return files


def extract_day_from_filename(filename):
    """
    Extract the last 8-digit date before the extension.
    """
    m = re.search(r'(\d{8})(?=\.[^.]+$)', filename)
    return m.group(1) if m else None


def decompress_xz_to_temp(filepath):
    """
    Decompress .xz file to a temporary .pcap file and return its path.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()
    cmd = ["xz", "-d", "-c", filepath]
    with open(tmp.name, "wb") as out:
        subprocess.run(cmd, stdout=out, check=True)
    return tmp.name


def merge_files_for_day(files, out_path):
    """
    Use mergecap to merge multiple PCAP files into one (no capture comments).
    """
    cmd = ["mergecap", "-F", "pcap", "-w", out_path] + files
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        print(result.stderr.decode(), file=sys.stderr)
        abort(f"mergecap failed for {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge PCAP files by date suffix.")
    parser.add_argument("input_dir", help="Directory containing input PCAP files.")
    parser.add_argument("output_dir", help="Destination directory for merged files.")
    parser.add_argument("mask", help="Mask for output filenames (e.g. 'darknet').")
    parser.add_argument("-g", "--no-gzip", action="store_true",
                        help="Do not compress output files (default: compress as .pcap.gz)")
    args = parser.parse_args()

    dir_in = Path(args.input_dir)
    dir_out = Path(args.output_dir)
    mask = args.mask
    compress = not args.no_gzip

    ensure_tool("mergecap")
    ensure_tool("xz")

    if not dir_in.exists():
        abort(f"Input directory '{dir_in}' does not exist.")
    if dir_out.exists():
        abort(f"Output directory '{dir_out}' already exists.")
    dir_out.mkdir()

    files = list_pcaps(dir_in)
    print(f"Found {len(files)} PCAP files in {dir_in}.")

    # Group files by date
    groups = {}
    for f in files:
        day = extract_day_from_filename(os.path.basename(f))
        if not day:
            print(f"⚠️  Skipping {f} (no date found)")
            continue
        groups.setdefault(day, []).append(f)

    if not groups:
        abort("No valid date patterns found in filenames.")

    temp_files = []

    try:
        for day, day_files in sorted(groups.items()):
            print(f"📅  Merging {len(day_files):3d} files for day {day}...")
            prepared_files = []
            for f in day_files:
                if f.endswith(".xz"):
                    print(f"  Decompressing {os.path.basename(f)}...")
                    tmp_path = decompress_xz_to_temp(f)
                    temp_files.append(tmp_path)
                    prepared_files.append(tmp_path)
                else:
                    prepared_files.append(f)

            output_base = dir_out / f"{mask}_{day}.pcap"
            merge_files_for_day(prepared_files, str(output_base))

            if compress:
                gz_path = str(output_base) + ".gz"
                print(f"   Compressing to {gz_path}...")
                with open(output_base, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(output_base)

        print("\n✅  Done! All daily files merged successfully.")

    finally:
        # Cleanup temporary decompressed files
        for tmp in temp_files:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
