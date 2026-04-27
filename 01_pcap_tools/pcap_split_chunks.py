#!/usr/bin/env python3
"""
pcap_split_chunks.py
------------------
Split a PCAP/PCAP.GZ/PCAP.XZ file into smaller chunks,
each containing a specified maximum number of records.

Usage:
    python split_pcap.py <folder|input_pcap|input_pcap.gz|input_pcap.xz> <destination_folder> [max_records] [-g]

Example:
    python split_pcap.py network_capture.pcap.gz output_folder 500000
    python split_pcap.py ./pcaps/ output_folder 1000000 --no-gzip
"""

import sys
import os
import subprocess
import gzip
import lzma
import argparse
from tqdm import tqdm


def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: tshark is not installed or not is in the PATH.")
        sys.exit(2)


def decompress_pcap(input_file):
    """Decompress the input file if necessary and return the uncompressed file name."""
    input_dir = os.path.dirname(input_file)
    if input_file.endswith('.pcap.gz'):
        print(f"Decompressing {input_file}...")
        output_file = os.path.join(input_dir, os.path.basename(input_file)[:-3])
        with gzip.open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(f_in.read())
        remove_original = True

    elif input_file.endswith('.pcap.xz'):
        print(f"Decompressing {input_file}...")
        output_file = os.path.join(input_dir, os.path.basename(input_file)[:-3])
        with lzma.open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            f_out.write(f_in.read())
        remove_original = True

    else:
        print(f"Input file {input_file} is not compressed.")
        output_file = input_file
        remove_original = False

    return output_file, remove_original


def split_pcap(input_file, output_folder, max_records=500000, compress=True):
    """Split the input PCAP file into smaller chunks."""
    if os.path.isdir(input_file):
        pcap_files = [os.path.join(input_file, f) for f in os.listdir(input_file)
                      if f.endswith('.pcap') or f.endswith('.pcap.gz') or f.endswith('.pcap.xz')]
        for pcap in pcap_files:
            split_pcap(pcap, output_folder, max_records, compress)
        return

    uncompressed_file, remove_file = decompress_pcap(input_file)
    uncompressed_file_without_ext = uncompressed_file.replace(".pcap", "")
    base_name = os.path.basename(uncompressed_file_without_ext)

    if not output_folder.endswith(os.sep):
        output_folder += os.sep

    output_file = f"{output_folder}{base_name}_sp.pcap"

    print(f"Splitting {uncompressed_file} into chunks of {max_records} records...")
    cmd = ["editcap", "-c", str(max_records), uncompressed_file, output_file]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)

    if compress:
        print("\nCompressing output .pcap files with gzip...")
        files_to_compress = [f for f in os.listdir(output_folder) if f.endswith(".pcap")]

        for file in tqdm(files_to_compress):
            file_path = os.path.join(output_folder, file)
            with open(file_path, 'rb') as f_in, gzip.open(file_path + ".gz", 'wb') as f_out:
                f_out.writelines(f_in)
            os.remove(file_path)

    if remove_file:
        print(f"Removing temporary uncompressed file: {uncompressed_file}")
        os.remove(uncompressed_file)

    print("✅ Splitting completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split PCAP files into smaller chunks.")
    parser.add_argument("input_pcap", help="Folder or PCAP file (.pcap, .pcap.gz, .pcap.xz)")
    parser.add_argument("output_folder", help="Destination folder for chunked PCAPs")
    parser.add_argument("max_records", nargs="?", default=500000, type=int,
                        help="Max records per file (default: 500000)")
    parser.add_argument("-g", "--no-gzip", action="store_true",
                        help="Do not compress output PCAP chunks")

    args = parser.parse_args()

    check_tshark()

    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)
    else:
        print(f"ERROR: Output folder {args.output_folder} already exists. Please specify a non-existing folder.")
        sys.exit(1)

    split_pcap(args.input_pcap, args.output_folder, args.max_records, compress=not args.no_gzip)
