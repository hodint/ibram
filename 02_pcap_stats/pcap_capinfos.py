#!/usr/bin/env python3
"""
capinfos_to_ndjson.py - Runs capinfos on a list of pcap/pcap.gz/pcap.xz files
and writes an NDJSON with fixed fields (including fields inside "Interface #0 info",
but without the 'Interface #0 info:' line itself) for each file.

Usage:
    python capinfos_to_ndjson.py -w output.ndjson <input_paths...>

Where <input_paths...> can be directories, files, or wildcards (e.g. data/*.pcap*).
Requirements:
    - Python 3.6+
    - capinfos (part of Wireshark) installed and in PATH

Example:
    python capinfos_to_ndjson.py -w capinfos_output.ndjson ./pcaps/*.pcap.gz ./more_pcaps/
"""
import argparse
import subprocess
import json
import re
import os
import sys
from glob import glob


# Parsing utilities
def parse_size(value):
    if not value:
        return None
    s = str(value).strip().lower().replace(",", ".")
    # Examples: "47 MB", "500 k", "88080384", "84 MB"
    m = re.match(r"^([\d\.]+)\s*([kmgt]?b?)$", s)
    if m:
        num = float(m.group(1))
        unit = m.group(2)
        if unit in ("b", ""):
            return int(num)
        if unit.startswith("k"):
            return int(num * 1024)
        if unit.startswith("m"):
            return int(num * 1024**2)
        if unit.startswith("g"):
            return int(num * 1024**3)
        if unit.startswith("t"):
            return int(num * 1024**4)
    # fallback: Extract first integer found
    digits = re.findall(r"\d+", s)
    if digits:
        try:
            return int(digits[0])
        except:
            return None
    return None


def safe_int(v, default=0):
    if v is None:
        return default
    try:
        if isinstance(v, int):
            return v
        s = str(v).strip()
        # Remove dots/commas for thousands separators
        s = s.replace(".", "").replace(",", "")
        return int(s)
    except:
        # try float -> int
        try:
            return int(float(str(v).replace(",", ".")))
        except:
            return default


def safe_float(v, default=0.0):
    if v is None:
        return default
    try:
        if isinstance(v, float):
            return v
        s = str(v).strip().replace(",", ".")
        # extract first float-like substring
        m = re.search(r"[-+]?\d+(\.\d+)?", s)
        if m:
            return float(m.group(0))
        return float(s)
    except:
        return default


# ---------- capinfos ----------
def run_capinfos(filepath):
    try:
        p = subprocess.run(["capinfos", filepath], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("Error: 'capinfos' binary was not found in PATH.", file=sys.stderr)
        return None
    if p.returncode != 0 and not p.stdout:
        # capinfos returned error
        return None

    return p.stdout.splitlines()


# ---------- output parsing ----------
def parse_capinfos(lines):
    file_fields = {}
    iface_fields = {}
    in_iface_block = False

    for idx, raw in enumerate(lines):
        line = raw.rstrip("\n")
        stripped = line.strip()

        # Detect "Number of interfaces in file" to check if > 1
        if stripped.lower().startswith("number of interfaces in file"):
            # Format: "Number of interfaces in file: 1"
            parts = line.split(":", 1)
            if len(parts) > 1 and parts[1].strip() != "1":
                # If more than 1 interface, we skip
                return None

        # Detect start of "Interface #0 info" block
        if stripped.lower().startswith("interface #0 info"):
            in_iface_block = True
            continue

        # In this block the lines are indented: key = value
        if in_iface_block:
            # If the line is indented, parse key = value
            if len(line) > 0 and (line[0] == " " or line[0] == "\t"):
                if "=" in line:
                    left, right = line.split("=", 1)
                    key = left.strip()
                    val = right.strip()
                    iface_fields[key] = val
                    continue
                else:
                    # Lines without "=" inside iface block are ignored
                    continue
            else:
                # Not indented: end of iface block
                in_iface_block = False

        # Out of iface block: parse key: value lines
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            val = v.strip()
            file_fields[key] = val
            continue
        # Lines without ":" are ignored


    encapsulation = iface_fields.get("Encapsulation") or file_fields.get("File encapsulation")
    capture_length = None
    if "Capture length" in iface_fields:
        capture_length = safe_int(re.search(r"\d+", iface_fields.get("Capture length", "")).group(0)) if re.search(r"\d+", iface_fields.get("Capture length", "")) else 0
    else:
        psl = file_fields.get("Packet size limit", "")
        m = re.search(r"file hdr[: ]*\s*(\d+)", psl)
        if m:
            capture_length = safe_int(m.group(1))
    if capture_length is None:
        capture_length = 0

    # Time precision
    time_precision = iface_fields.get("Time precision") or file_fields.get("File timestamp precision")

    # Time ticks per second
    time_ticks = None
    if "Time ticks per second" in iface_fields:
        time_ticks = safe_int(iface_fields.get("Time ticks per second"))
    else:
        # Not present
        time_ticks = 0

    stat_entries = safe_int(iface_fields.get("Number of stat entries", 0))
    interface_packets = safe_int(iface_fields.get("Number of packets", 0))

    # Main fields
    file_name = file_fields.get("File name")
    number_of_packets = file_fields.get("Number of packets")  # keep the textual format ("1.101 k")
    file_size_bytes = parse_size(file_fields.get("File size", "")) or parse_size(file_fields.get("File size", "")) or None
    data_size_bytes = parse_size(file_fields.get("Data size", "")) or None
    capture_duration_seconds = safe_float(file_fields.get("Capture duration", "0"))
    earliest_packet_time = file_fields.get("Earliest packet time")
    latest_packet_time = file_fields.get("Latest packet time")
    data_byte_rate = safe_float(file_fields.get("Data byte rate", "0"))
    data_bit_rate = file_fields.get("Data bit rate")  # text such as "14 kbps"
    average_packet_size = safe_float(file_fields.get("Average packet size", "0"))
    average_packet_rate = file_fields.get("Average packet rate")  # text such as "28 packets/s"
    strict_time_order = (file_fields.get("Strict time order", "").lower() == "true")

    # Construct result dict with fixed fields sorted
    result = {
        "file_name": file_name,
        # "number_of_packets": number_of_packets,
        "number_of_packets": safe_int(interface_packets, 0),  # Use the interface packets
        "file_size_bytes": file_size_bytes,
        "data_size_bytes": data_size_bytes,
        "capture_duration_seconds": capture_duration_seconds,
        "earliest_packet_time": earliest_packet_time,
        "latest_packet_time": latest_packet_time,
        "data_byte_rate": data_byte_rate,
        "data_bit_rate": data_bit_rate,
        "average_packet_size": average_packet_size,
        "average_packet_rate": average_packet_rate,
        "strict_time_order": strict_time_order,
        # Interface #0 info fields (without the "Interface #0 info:" header)
        "encapsulation": encapsulation,
        "capture_length": safe_int(capture_length, 0),
        "time_precision": time_precision,
        "time_ticks_per_second": safe_int(time_ticks, 0),
        "stat_entries": safe_int(stat_entries, 0),
        # "interface_packets": safe_int(interface_packets, 0),
    }

    return result


# ---------- File utilites ----------
def collect_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for ext in ("*.pcap", "*.pcap.gz", "*.pcap.xz"):
                files.extend(glob(os.path.join(p, ext)))
        else:
            # expand wildcards and explicit files
            files.extend(glob(p))
    # remove duplicates and sort
    return sorted(set(files))


# ---------- MAIN! ----------
def main():
    parser = argparse.ArgumentParser(description="capinfos -> NDJSON")
    parser.add_argument("inputs", nargs="+", help="Directories, files or wildcards")
    parser.add_argument("-w", required=True, help="NDJSON output file")
    args = parser.parse_args()

    files = collect_files(args.inputs)
    if not files:
        print("No files found.", file=sys.stderr)
        sys.exit(1)

    with open(args.w, "w", encoding="utf-8") as out:
        for fpath in files:
            lines = run_capinfos(fpath)
            if not lines:
                print(f"warning: capinfos failure or without output: {fpath}", file=sys.stderr)
                continue
            info = parse_capinfos(lines)
            if info is None:
                print(f"warning: Interface number > 1: {fpath}", file=sys.stderr)
                continue
            out.write(json.dumps(info, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()
