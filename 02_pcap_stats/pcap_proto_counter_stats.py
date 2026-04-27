#!/usr/bin/env python3
import os
import sys
import json
from collections import defaultdict, Counter
import pandas as pd
import matplotlib.pyplot as plt
import re

# ------------------------------------------------------------
# Protocol number to name mapping
# Add new ones when warnings appear
# ------------------------------------------------------------
PROTOCOL_MAP = {
    "0": "HOPOPT",
    "1": "ICMP",
    "2": "IGMP",
    "4": "IP-in-IP",
    "5": "ST",
    "6": "TCP",
    "8": "EGP",
    "17": "UDP",
    "27": "RDP",
    "33": "DCCP",
    "41": "IPv6",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "89": "OSPF",
    "132": "SCTP",
    "136": "UDPLite",
    "137": "MPLS-in-IP",
    "138": "MANET",
    "143": "ETHERNET",
    "255": "Reserved",
}

# ------------------------------------------------------------
# Extract date from filename (YYYYMMDD)
# ------------------------------------------------------------
def extract_date(filename):
    m = re.search(r"(20\d{6})", filename)
    return m.group(1) if m else None

# ------------------------------------------------------------
# Read NDJSON files (one JSON object per line)
# ------------------------------------------------------------
def read_records(paths):
    records = []
    for path in paths:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except:
                    print(f"⚠️ Skipping invalid JSON in {path}")
                    continue
                records.append(rec)
    return records

# ------------------------------------------------------------
# Group counts by day (sum protocols across files of same day)
# ------------------------------------------------------------
def group_by_day(records):
    day_counts = defaultdict(Counter)
    unknown_protocols = set()

    for rec in records:
        filename = rec["file"]
        date = extract_date(filename)
        if not date:
            continue

        for k, v in rec.items():
            if k.isdigit():
                name = PROTOCOL_MAP.get(k)
                if not name:
                    name = f"PROTO_{k}"
                    unknown_protocols.add(k)
                day_counts[date][name] += v

    return day_counts, unknown_protocols

# ------------------------------------------------------------
# Build DataFrame with totals and percentage columns
# ------------------------------------------------------------
def build_dataframe(day_counts):
    df = pd.DataFrame.from_dict(day_counts, orient="index").fillna(0).astype(int)

    df["total"] = df.sum(axis=1)

    preferred = ["total", "TCP", "UDP", "ICMP"]
    others = sorted(col for col in df.columns if col not in preferred)
    df = df[[c for c in preferred if c in df.columns] + others]

    # Add percentage columns
    for col in df.columns:
        if col != "total":
            # df[col + "_pct"] = (df[col] / df["total"]) * 100
            df[col + "_pct"] = ((df[col] / df["total"]) * 100).round(2)

    return df.sort_index()

# ------------------------------------------------------------
# Compute totals across all days
# ------------------------------------------------------------
def compute_global_totals(day_counts):
    total = Counter()
    for c in day_counts.values():
        total.update(c)
    return total

# ------------------------------------------------------------
# Generate stacked bar chart - absolute values
# ------------------------------------------------------------
def create_stacked_chart_absolute(df, out_png, out_pdf):
    proto_cols = [c for c in df.columns if not c.endswith("_pct") and c != "total"]

    plt.figure(figsize=(12, 6))
    bottom = None

    for col in proto_cols:
        if bottom is None:
            plt.bar(df.index, df[col], label=col)
            bottom = df[col]
        else:
            plt.bar(df.index, df[col], bottom=bottom, label=col)
            bottom = bottom + df[col]

    plt.ylabel("Packets (absolute count)")
    plt.xticks(rotation=45, ha="right")
    plt.title("Daily Traffic (Stacked by Protocol - Absolute Values)")
    plt.legend(loc="upper left")
    plt.tight_layout()

    plt.savefig(out_png)
    plt.savefig(out_pdf)
    plt.close()


# ------------------------------------------------------------
# Generate stacked bar chart - percentages (100% stacked)
# ------------------------------------------------------------
def create_stacked_chart_percentage(df, out_png, out_pdf):
    proto_cols = [c for c in df.columns if not c.endswith("_pct") and c != "total"]

    share = df[proto_cols].div(df["total"], axis=0)

    plt.figure(figsize=(12, 6))
    bottom = None

    for col in proto_cols:
        plt.bar(df.index, share[col], bottom=bottom, label=col)
        bottom = share[col] if bottom is None else bottom + share[col]

    plt.ylabel("Traffic Share (%)")
    plt.xticks(rotation=45, ha="right")
    plt.title("Daily Traffic (100% Stacked by Protocol)")
    plt.legend(loc="upper right")
    plt.tight_layout()

    plt.savefig(out_png)
    plt.savefig(out_pdf)
    plt.close()


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.txt>")
        sys.exit(1)

    input_paths = sys.argv[1:]
    records = read_records(input_paths)

    print(f"✓ Read {len(records)} records.")

    day_counts, unknown = group_by_day(records)

    if unknown:
        print("⚠️ Unknown protocols found:", ", ".join(sorted(unknown)))
        print("   Add them to PROTOCOL_MAP dictionary in this script and re-run.\n")

    df_daily = build_dataframe(day_counts)
    totals = compute_global_totals(day_counts)

    # Output filenames based on the first input
    base = os.path.splitext(input_paths[0])[0]
    out_daily = base + "_daily.csv"
    out_total = base + "_total.csv"

    df_daily.to_csv(out_daily, sep=";")
    print("✓ Daily summary ->", out_daily)

    df_total = pd.DataFrame(totals, index=["total"]).fillna(0).astype(int)
    preferred = ["TCP", "UDP", "ICMP"]
    others = sorted(col for col in df_total.columns if col not in preferred)
    df_total = df_total[[c for c in preferred if c in df_total.columns] + others]

    total_sum = df_total.sum(axis=1).iloc[0]
    for col in df_total.columns:
        # df_total[col + "_pct"] = (df_total[col] / total_sum) * 100
        df_total[col + "_pct"] = ((df_total[col] / total_sum) * 100).round(2)

    df_total.to_csv(out_total, sep=";")
    print("✓ Total summary  ->", out_total)

    # Figures
    # Absolute-value stacked chart
    create_stacked_chart_absolute(df_daily,
                                base + "_stacked_absolute.png",
                                base + "_stacked_absolute.pdf")
    print("✓ Absolute stacked chart ->", base + "_stacked_absolute.*")

    # Percentage stacked chart
    create_stacked_chart_percentage(df_daily,
                                    base + "_stacked_percent.png",
                                    base + "_stacked_percent.pdf")
    print("✓ Percentage stacked chart ->", base + "_stacked_percent.*")

    print("\n✅ DONE.\n")

if __name__ == "__main__":
    main()
