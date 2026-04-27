#!/usr/bin/env python3
"""
Aggregate enriched ICMP CSV files by ip_src, ip_src_in_payload, ip_dst_in_payload, payload_length_bytes.

Reads files matching "*_1_*_enriched.csv" from input directory,
processes them in alphabetical order, and outputs:
- CSV files for non-aggregated records (suffix: -icmp_enriched_stats.csv)
- NDJSON files for aggregated records (suffix: -icmp_enriched_stats.ndjson)
"""

import argparse
import gzip
import json
from pathlib import Path
import pandas as pd

# Filename mask used
filename_mask = 'icmp_enriched_stats'

# CSV columns
COLUMNS = [
    "timestamp", "ip_version", "ip_orig_tos", "ip_tos", "ip_prec", "ip_dscp",
    "ip_enc", "ip_len", "ip_id", "ip_ttl", "ip_chksum", "ip_src", "ip_dst",
    "ip_options", "icmp_type", "icmp_code", "icmp_id", "icmp_seq",
    "icmp_chksum", "payload_hex", "key", "IBR_info",
]

# Fields that define aggregation (extracted from IBR_info)
GROUP_COLS = ["ip_src", "ip_src_in_payload", "ip_dst_in_payload", "payload_length_bytes"]


def parse_ibr_info(ibr_info_str):
    """Parse IBR_info from string to dictionary."""
    if isinstance(ibr_info_str, dict):
        return ibr_info_str
    try:
        # Handle both JSON format (true/false) and Python format (True/False)
        ibr_info_str = str(ibr_info_str)
        # Try JSON first
        try:
            return json.loads(ibr_info_str.replace("'", '"').replace("True", "true").replace("False", "false"))
        except json.JSONDecodeError:
            # Fall back to eval for Python dict format
            return eval(ibr_info_str)
    except Exception:
        return {}


def read_csv_any(path: Path):
    """Read CSV or CSV.GZ with ';' separator and add source_file column."""
    if str(path).endswith(".gz"):
        df = pd.read_csv(path, sep=";", names=COLUMNS, compression="gzip")
    else:
        df = pd.read_csv(path, sep=";", names=COLUMNS)

    # Filter: only ICMP Echo Request (type=8, code=0)
    df = df[((df["icmp_type"] == 8) & (df["icmp_code"] == 0)) |
            ((df["icmp_type"] == '8') & (df["icmp_code"] == '0'))].copy()

    df["source_file"] = path.name

    # Parse IBR_info and extract needed fields
    df['IBR_info_parsed'] = df['IBR_info'].apply(parse_ibr_info)
    df['ip_src_in_payload'] = df['IBR_info_parsed'].apply(lambda x: x.get('ip_src_in_payload', False))
    df['ip_dst_in_payload'] = df['IBR_info_parsed'].apply(lambda x: x.get('ip_dst_in_payload', False))
    df['payload_length_bytes'] = df['IBR_info_parsed'].apply(lambda x: x.get('payload_length_bytes', 0))
    return df


def build_reason():
    """Build reason text with the list of fields."""
    return "ip_src;ip_src_in_payload;ip_dst_in_payload;payload_length_bytes"


def build_agg_record(group: pd.DataFrame, first_filename: str) -> dict:
    """Create NDJSON dictionary for an aggregate (count >= 1)."""
    ts_start = group["timestamp"].min()
    ts_end = group["timestamp"].max()
    keys = sorted(group["key"].astype(str).unique().tolist())

    # Get the minor key value and use it as representative
    minor_key = keys[0] if keys else None
    ibr_flow_id = f"{minor_key}-agg" if minor_key else "agg"

    # Sorted list of unique destination IPs
    ip_dst_list = sorted(group["ip_dst"].astype(str).unique().tolist())

    # Take values (in principle all equal within the group)
    sample = group.iloc[0]

    # Helper to convert numpy types to native Python types
    def to_native(val):
        if hasattr(val, 'item'):
            return val.item()
        return val

    info = {
        "reason": build_reason(),
        "ip_src": str(sample["ip_src"]),
        "icmp_type": to_native(sample["icmp_type"]),
        "icmp_code": to_native(sample["icmp_code"]),
        "IBR_info": str(sample["IBR_info"]),
        "ip_src_in_payload": str(sample["ip_src_in_payload"]),
        "ip_dst_in_payload": str(sample["ip_dst_in_payload"]),
        "payload_length_bytes": to_native(sample["payload_length_bytes"]),
        "ip_dst_list": ip_dst_list,
        "ip_dst_count": len(ip_dst_list),
        "first_filename": first_filename,
        "count": len(group),
    }

    rec = {
        'ibr_flow_id': ibr_flow_id,
        "ts_start": to_native(ts_start),
        "ts_end": to_native(ts_end),
        "action": "aggregate",
        "traffic_list": keys,
        "count": len(group),
        "info": info,
    }
    return rec


def collect_input_files(input_paths):
    """Collect all CSV files from input paths (files or directories)."""
    all_files = []
    for input_path in input_paths:
        p = Path(input_path)
        if p.is_dir():
            # If it's a directory, get all CSV files matching pattern _1.csv or _1.csv.gz or containing _1_
            # and must contain "_enriched" in the filename
            files = sorted([
                fp for fp in p.iterdir()
                if fp.is_file() and '_enriched' in fp.name and
                   (fp.name.endswith("_1.csv") or fp.name.endswith("_1.csv.gz") or
                    ('_1_' in fp.name and fp.name.endswith(".csv")) or
                    ('_1_' in fp.name and fp.name.endswith(".csv.gz")))
            ])
            all_files.extend(files)
        elif p.is_file():
            # If it's a file, add it directly if it matches the pattern and contains "_enriched"
            if '_enriched' in p.name and \
               (p.name.endswith("_1.csv") or p.name.endswith("_1.csv.gz") or
                ('_1_' in p.name and (p.name.endswith(".csv") or p.name.endswith(".csv.gz")))):
                all_files.append(p)
    return sorted(all_files)

def get_output_base(filename: str) -> str:
    """Remove .csv or .csv.gz extension from filename."""
    if filename.endswith(".csv.gz"):
        return filename[:-7]
    elif filename.endswith(".csv"):
        return filename[:-4]
    return filename


def flush_groups(df_flush, output_dir, gzip_output):
    """
    Write groups to output files based on count:
    - count > 1: NDJSON aggregate records
    - count == 1: CSV with original format, sorted by key
    """
    # Group by GROUP_COLS
    for _, g in df_flush.groupby(GROUP_COLS, sort=False):
        count = len(g)
        last_file = g.iloc[-1]["last_filename"]
        base = get_output_base(last_file)

        if count > 1:
            # Aggregated: write to NDJSON
            rec = build_agg_record(g, g.iloc[0]["first_filename"])
            out_name = base + f"_{filename_mask}.ndjson"
            if gzip_output:
                out_name += ".gz"
            out_path = output_dir / out_name

            if gzip_output:
                with gzip.open(out_path, "at", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            else:
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
        else:
            # Single occurrence: write to CSV in original format, sorted by key
            out_name = base + f"_{filename_mask}.csv"
            if gzip_output:
                out_name += ".gz"
            out_path = output_dir / out_name

            # Select only original COLUMNS and sort by key
            row = g[COLUMNS].sort_values(by="key")  # type: ignore[call-overload]

            if gzip_output:
                with gzip.open(out_path, "at", encoding="utf-8") as f:
                    row.to_csv(f, sep=";", header=False, index=False)
            else:
                with open(out_path, "a", encoding="utf-8") as f:
                    row.to_csv(f, sep=";", header=False, index=False)


def dump_final_analysis(analysis_df, output_dir, gzip_output):
    """
    Write final analysis results:
    - count > 1: NDJSON aggregate records
    - count == 1: CSV with original format
    """
    if analysis_df.empty:
        print("No remaining records to dump.")
        return

    print(f"\nDumping {len(analysis_df):,} remaining records...")

    ndjson_count = 0
    csv_count = 0

    for group_key, g in analysis_df.groupby(GROUP_COLS, sort=False):
        g = g.reset_index(drop=True)
        count = len(g)
        last_source = g.iloc[-1]["last_filename"]
        base = get_output_base(last_source)

        if count > 1:
            # Aggregated: write to NDJSON
            rec = build_agg_record(g, g.iloc[0]["first_filename"])
            out_name = base + f"_{filename_mask}.ndjson"
            if gzip_output:
                out_name += ".gz"
            out_path = output_dir / out_name

            if gzip_output:
                with gzip.open(out_path, "at", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            else:
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            ndjson_count += 1
        else:
            # Single occurrence: write to CSV in original format
            out_name = base + f"_{filename_mask}.csv"
            if gzip_output:
                out_name += ".gz"
            out_path = output_dir / out_name

            row = g[COLUMNS].sort_values(by="key")  # type: ignore[call-overload]

            if gzip_output:
                with gzip.open(out_path, "at", encoding="utf-8") as f:
                    row.to_csv(f, sep=";", header=False, index=False)
            else:
                with open(out_path, "a", encoding="utf-8") as f:
                    row.to_csv(f, sep=";", header=False, index=False)
            csv_count += 1

    print(f"  Written {ndjson_count:,} aggregated records (NDJSON), {csv_count:,} single records (CSV)")


def process_single_file(fpath, analysis_df, output_dir, gzip_output):
    """Process a single input file and update the analysis dataframe."""
    prev_count = len(analysis_df)

    df_new = read_csv_any(fpath)
    new_records = len(df_new)

    # Initialize first_filename and last_filename in new rows
    df_new["first_filename"] = df_new["source_file"]
    df_new["last_filename"] = df_new["source_file"]

    # If analysis_df is empty, just return the new data
    if analysis_df.empty:
        print(f"  Loaded: {new_records:,} | Flushed: 0 | Remaining in memory: {new_records:,} (Δ+{new_records:,})")
        return df_new

    # Mark existing groups (before adding new file)
    # Create a set of existing group keys
    existing_groups = set(analysis_df.groupby(GROUP_COLS, sort=False).groups.keys())

    # Concatenate to analysis set
    analysis_df = pd.concat([analysis_df, df_new], ignore_index=True)

    # Update last_filename for all rows from current file
    analysis_df.loc[analysis_df["source_file"] == fpath.name, "last_filename"] = fpath.name

    # Find groups that have entries from the current file
    current_file_mask = analysis_df["source_file"] == fpath.name
    groups_with_new_entries = set(
        analysis_df[current_file_mask].groupby(GROUP_COLS, sort=False).groups.keys()
    )

    # Groups that existed before but did NOT receive new entries should be flushed
    groups_to_flush = existing_groups - groups_with_new_entries

    flushed_count = 0
    flushed_groups = 0
    if groups_to_flush:
        # Create a mask for rows belonging to groups that should be flushed
        # We need to identify rows by their GROUP_COLS values
        flush_mask = analysis_df.apply(
            lambda row: tuple(row[col] for col in GROUP_COLS) in groups_to_flush,
            axis=1
        )

        if bool(flush_mask.any()):
            df_flush = pd.DataFrame(analysis_df[flush_mask]).copy()
            flushed_count = len(df_flush)

            # Write records for each group (NDJSON for aggregates, CSV for singles)
            flush_groups(df_flush, output_dir, gzip_output)
            flushed_groups = len(groups_to_flush)

            # Remove flushed rows from analysis set
            analysis_df = pd.DataFrame(analysis_df[~flush_mask]).copy()

    remaining_count = len(analysis_df)

    print(f"  Loaded: {new_records:,} | Flushed: {flushed_count:,} ({flushed_groups:,} groups) | Remaining in memory: {remaining_count:,} (Δ{remaining_count - prev_count:+,})")

    return analysis_df


def process_files(all_files, output_dir, gzip_output):
    """Process all files in order."""
    # Initialize empty DataFrame with proper columns
    extra_cols = ["source_file", "first_filename", "last_filename",
                  "IBR_info_parsed",
                  "ip_src_in_payload", "ip_dst_in_payload",
                  "payload_length_bytes"]
    analysis_df = pd.DataFrame(columns=COLUMNS + extra_cols)

    last_file = None
    for fpath in all_files:
        print(f"Processing {fpath.name}")
        analysis_df = process_single_file(fpath, analysis_df, output_dir, gzip_output)
        last_file = fpath

    # After processing all files, dump analysis set
    if last_file:
        dump_final_analysis(analysis_df, output_dir, gzip_output)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Aggregate ICMP packets by fields and generate NDJSON / CSV."
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        nargs="+",
        help="Input directory or files (*.csv, *.csv.gz). Can be one or more files, or a directory.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="Directory where output files will be saved",
    )
    parser.add_argument(
        "-g",
        "--gzip",
        action="store_true",
        help="If set, output files will not be compressed with gzip",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect all input files from the provided paths
    all_files = collect_input_files(args.input)
    if not all_files:
        print("Error: No input files found.")
        return

    # Process the collected files
    process_files(all_files, output_dir, gzip_output=(not args.gzip))


if __name__ == "__main__":
    main()
