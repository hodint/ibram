#!/usr/bin/env python3
import re
import csv
import sys

def parse_size(s):
    """Convert sizes like '1.201 kB' or '9.960 bytes' to bytes (int)."""
    parts = s.split()
    if len(parts) == 1:  # rare case: number only
        return int(float(parts[0]))
    num, unit = parts
    num = float(num.replace(",", "."))  # handle decimals and commas
    unit = unit.strip()

    factor = {
        "bytes": 1,
        "B": 1,
        "kB": 1000,
        "MB": 1000000,
        "GB": 1000000000,
    }

    if unit not in factor:
        raise ValueError(f"Unidad desconocida: {unit} en '{s}'")

    return int(num * factor[unit])

def convert_tshark_to_csv(infile, outfile):
    with open(infile, "r", encoding="utf-8") as f:
        lines = f.readlines()

    data = []
    for line in lines:
        if "<->" not in line:
            continue
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 12:
            continue

        # Address and port (robust against IPv6)
        try:
            addr_a, port_a = parts[0].rsplit(":", 1)
            addr_b, port_b = parts[2].rsplit(":", 1)
        except ValueError:
            # malformed line, skip it
            continue

        pkts_ab = int(parts[3])
        bytes_ab = parse_size(parts[4] + " " + parts[5])

        pkts_ba = int(parts[6])
        bytes_ba = parse_size(parts[7] + " " + parts[8])

        pkts_total = int(parts[9])
        bytes_total = parse_size(parts[10] + " " + parts[11])

        start = float(parts[12].replace(",", "."))
        duration = float(parts[13].replace(",", "."))

        # Compute bits/s if duration > 0
        bits_ab = (bytes_ab * 8 / duration) if duration > 0 else 0
        bits_ba = (bytes_ba * 8 / duration) if duration > 0 else 0

        row = [
            addr_a, port_a, addr_b, port_b,
            pkts_total, bytes_total, "",  # Empty Stream ID
            pkts_ab, bytes_ab,
            pkts_ba, bytes_ba,
            start, duration, bits_ab, bits_ba, ""  # Empty Flows
        ]
        data.append(row)

    # Write Wireshark-style CSV
    headers = [
        "Dirección A","Puerto A","Dirección B","Puerto B",
        "Paquetes","Bytes","Stream ID",
        "Packets A → B","Bytes A → B",
        "Packets B → A","Bytes B → A",
        "Inicio rel","Duración","Bits/s A → B","Bits/s B → A","Flows"
    ]

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(data)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_tshark_format_file.txt> <ouput_wireshark_format_file.csv>")
        sys.exit(1)
    convert_tshark_to_csv(sys.argv[1], sys.argv[2])
