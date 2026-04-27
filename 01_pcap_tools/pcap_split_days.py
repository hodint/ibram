#!/usr/bin/env python3
"""
pcap_split_by_day.py
--------------------
Split a PCAP/PCAP.GZ/PCAP.XZ file into daily PCAPs using tshark filters.

Output files (by default compressed) will be named:
    <input_base>-split_YYYYMMDD.pcap.gz
or, if --no-gzip:
    <input_base>-split_YYYYMMDD.pcap

Requirements:
    - Python 3
    - tshark available in PATH
    - tqdm (pip install tqdm)

Usage:
    python pcap_split_by_day.py <pcap|pcap.gz|pcap.xz|folder> <output_folder> [--no-gzip] [--workers N]
"""

import argparse
import gzip
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from tqdm import tqdm


def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: tshark is not installed or not is in the PATH.")
        sys.exit(2)


def decompress_to_temp(input_path):
    """
    If input_path is .pcap.gz or .pcap.xz, decompress to a temp file and return its path
    and a boolean indicating the temp should be removed later.
    If not compressed, return input_path and False.
    """
    if input_path.endswith(".pcap.gz"):
        tmp = tempfile.NamedTemporaryFile(prefix="pcap_unz_", suffix=".pcap", delete=False)
        tmp.close()
        print(f"Decompressing {input_path} -> {tmp.name} ...")
        with gzip.open(input_path, "rb") as f_in, open(tmp.name, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        return tmp.name, True
    elif input_path.endswith(".pcap.xz"):
        tmp = tempfile.NamedTemporaryFile(prefix="pcap_unxz_", suffix=".pcap", delete=False)
        tmp.close()
        print(f"Decompressing {input_path} -> {tmp.name} ...")
        with lzma.open(input_path, "rb") as f_in, open(tmp.name, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        return tmp.name, True
    else:
        # assume already .pcap
        return input_path, False


def collect_dates_from_pcap(pcap_path):
    """
    Use tshark to stream frame.time_epoch values and collect unique YYYYMMDD strings.
    Returns a sorted list of YYYYMMDD strings.
    """
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "frame.time_epoch"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    dates_set = set()
    count = 0
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                epoch = float(line.split()[0])
            except Exception:
                continue
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            ymd = dt.strftime("%Y%m%d")
            dates_set.add(ymd)
            count += 1
    finally:
        proc.stdout.close()
        proc.wait()

    if count == 0:
        print(f"WARNING: No packet timestamps read from {pcap_path}. The file may be empty or incompatible.")
    dates = sorted(dates_set)
    return dates


def epoch_from_ymd(ymd):
    """Return epoch seconds (UTC) for YYYYMMDD 00:00:00."""
    dt = datetime.strptime(ymd, "%Y%m%d").replace(tzinfo=timezone.utc)
    return dt.timestamp()


def build_output_name(input_base, ymd, compress=True):
    """
    Build output file name:
      input_base = 'traffic' (without .pcap)
    returns full filename (not path) like 'traffic-split_YYYYMMDD.pcap.gz' or .pcap
    """
    suffix = ".pcap.gz" if compress else ".pcap"
    return f"{input_base}-split_{ymd}{suffix}"


def split_for_dates(pcap_path, input_basename, output_folder, dates, compress=True):
    """
    For each date in dates, run tshark to extract packets where
    frame.time_epoch >= start and < end, and write to output file.
    """
    if not dates:
        print("No dates to process.")
        return

    # create progress bar
    print(f"\nCreating daily pcaps for {len(dates)} day(s)...")
    for ymd in tqdm(dates, desc="days"):
        start_epoch = epoch_from_ymd(ymd)
        # compute next day
        dt_next = datetime.strptime(ymd, "%Y%m%d") + timedelta(days=1)
        end_ymd = dt_next.strftime("%Y%m%d")
        end_epoch = epoch_from_ymd(end_ymd)

        out_name = build_output_name(input_basename, ymd, compress=compress)
        out_path = os.path.join(output_folder, out_name)
        # temporary uncompressed output .pcap if we will compress later
        tmp_out = out_path if not compress else out_path.replace(".pcap.gz", ".pcap")

        # Build display filter using numeric comparisons
        # Note: using -Y (display filter) and -w to write matched packets
        disp_filter = f"frame.time_epoch >= {start_epoch:.6f} && frame.time_epoch < {end_epoch:.6f}"
        cmd = ["tshark", "-r", pcap_path, "-Y", disp_filter, "-w", tmp_out]
        # Run command
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            print(f"\nERROR: tshark failed for date {ymd}. Command: {' '.join(cmd)}")
            continue

        # If we wrote an empty pcap (0 bytes or minimal header), remove it
        try:
            if os.path.exists(tmp_out) and os.path.getsize(tmp_out) == 24:
                # 24 bytes is typical empty pcap header size on some systems; double-check
                os.remove(tmp_out)
                # no file created for that date
                continue
        except OSError:
            pass

        # Compress if needed
        if compress:
            with open(tmp_out, "rb") as f_in, gzip.open(tmp_out + ".gz", "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(tmp_out)


def remove_uncompressed_temp(file_path, should_remove):
    """
    Remove temporary uncompressed file if it exists.
    """
    # Only remove the file if we were created
    if not should_remove:
        return

    # Remove the uncompressed temp file
    try:
        os.remove(file_path)
    except OSError:
        print(f"WARNING: Could not remove temporary file {file_path}")


def process_single_file(input_file, output_folder, max_dates=None, compress=True):
    """
    Process one input pcap (maybe compressed). Steps:
      - decompress to temp if needed
      - collect unique dates via tshark
      - for each date, extract packets with tshark -Y ... -w ...
      - compress outputs if requested
      - cleanup temp file
    """
    print(f"\nProcessing: {input_file}")

    pcap_uncompressed, should_remove = decompress_to_temp(input_file)

    # base name without .pcap or .pcap.gz/.pcap.xz
    base = os.path.basename(input_file)
    for ext in (".pcap.gz", ".pcap.xz", ".pcap"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break

    # Step 1: collect dates
    print("Scanning timestamps to detect dates (this may take a while for large files)...")
    dates = collect_dates_from_pcap(pcap_uncompressed)
    if not dates:
        print("No dates found, skipping file.")
        remove_uncompressed_temp(pcap_uncompressed, should_remove)
        return

    # Optional: Limit number of dates processed (for testing)
    if max_dates is not None:
        dates = dates[:max_dates]

    # Step 2: split per date
    split_for_dates(pcap_uncompressed, base, output_folder, dates, compress=compress)

    # Cleanup temporary uncompressed file
    remove_uncompressed_temp(pcap_uncompressed, should_remove)


def gather_input_files(input_path):
    """Return list of files to process (if directory provided, expand supported files)."""
    if os.path.isdir(input_path):
        files = []
        for f in sorted(os.listdir(input_path)):
            if f.endswith(".pcap") or f.endswith(".pcap.gz") or f.endswith(".pcap.xz"):
                files.append(os.path.join(input_path, f))
        return files
    else:
        return [input_path]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split PCAP by day using tshark")
    parser.add_argument("input", help="PCAP file (.pcap, .pcap.gz, .pcap.xz) or folder containing such files")
    parser.add_argument("output_folder", help="Destination folder for daily PCAPs (must NOT exist)")
    parser.add_argument("-g", "--no-gzip", action="store_true", help="Do not compress output chunks (default: compress)")
    parser.add_argument("--max-dates", type=int, default=None, help="Optional: limit the number of days processed (for testing)")
    args = parser.parse_args()

    check_tshark()

    # Ensure output folder exists, if exists -> error (keeps previous behavior)
    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder, exist_ok=True)
    else:
        print(f"ERROR: Output folder {args.output_folder} already exists. Please specify a non-existing folder.")
        sys.exit(1)

    compress = not args.no_gzip

    input_files = gather_input_files(args.input)
    if not input_files:
        print("No pcap files found to process.")
        sys.exit(0)

    # Process each file
    for f in input_files:
        process_single_file(f, args.output_folder, max_dates=args.max_dates, compress=compress)

    print("\n✅ All done.")
