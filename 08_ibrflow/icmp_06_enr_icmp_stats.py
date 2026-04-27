from pathlib import Path
import pandas as pd
import ipaddress
import os
import json
import argparse


# Default values
DEFAULT_FILE_MASK = "darknet_*_mod_non_fragmented_1_echoscan-ipid_echoscan-noipid.csv"

# ## Enrichement functions for IBR ICMP stats dataset
#
# These functions include some columns to the dataframe. These coloumns will be removed
# and the final information is moved to the IBR info dictionary column.


# This function converts the ip_src or ip_dst from ipaddress to hexadecimal
def ip_to_hex(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return ip.packed.hex()


def include_ip_hex_columns(df):
    df['ip_src_hex'] = df['ip_src'].apply(ip_to_hex)
    df['ip_dst_hex'] = df['ip_dst'].apply(ip_to_hex)
    return df


def include_flag_address_in_payload_columns(df):
    # Create two boolean colums with checking the payload_hex includes the hex representation of the IP addresses
    df['ip_src_in_payload'] = df.apply(lambda row: row['ip_src_hex'] in row['payload_hex'], axis=1)
    df['ip_dst_in_payload'] = df.apply(lambda row: row['ip_dst_hex'] in row['payload_hex'], axis=1)
    return df


def print_ip_address_in_payload_stats(filename, df):
    # Count the number of ocurrences where ip_src or ip_dst is found in the payload
    src_count = df['ip_src_in_payload'].sum()
    dst_count = df['ip_dst_in_payload'].sum()

    # Count the number of ocurrences where the ip_src and the ip_dst are both found in the payload
    both_count = df[(df['ip_src_in_payload']) & (df['ip_dst_in_payload'])].shape[0]

    print(f"Stats for file {filename}: Total: {df.shape[0]}. ip_src in payload: {src_count}. ip_dst in payload: {dst_count}. Both in payload: {both_count}.")

    # print(f"Number of payloads containing ip_src: {src_count}")
    # print(f"Number of payloads containing ip_dst: {dst_count}")
    # print(f"Number of payloads containing both ip_src and ip_dst: {both_count}")
    # print(f"Total number of payloads: {df.shape[0]}")


def include_payload_length_column(df):
    # Include a new columen with the length of the payload in bytes
    df['payload_length_bytes'] = df['payload_hex'].apply(lambda x: len(x) // 2)
    return df


def copy_info_to_ibrjson(df):
    # Copy the enrichment information to the IBR info dictionary column
    def update_ibr_info(row):
        ibr_info = row.get('IBR_info', {})
        if isinstance(ibr_info, str):
            ibr_info = {}
        ibr_info['ip_src_hex'] = row['ip_src_hex']
        ibr_info['ip_dst_hex'] = row['ip_dst_hex']
        ibr_info['ip_src_in_payload'] = row['ip_src_in_payload']
        ibr_info['ip_dst_in_payload'] = row['ip_dst_in_payload']
        ibr_info['payload_length_bytes'] = row['payload_length_bytes']
        return ibr_info

    df['IBR_info'] = df.apply(update_ibr_info, axis=1)
    return df


def remove_temp_columns(df):
    # Remove the temporary columns used for enrichment
    df = df.drop(columns=['ip_src_hex', 'ip_dst_hex', 'ip_src_in_payload', 'ip_dst_in_payload', 'payload_length_bytes'])
    return df


# Function to create the output filename based on input filename and the path
def create_output_filename(input_filename, output_folder, suffix="_enriched", gzip_output=False):
    basename = os.path.basename(str(input_filename))
    # Remove .gz if present to get the base extension
    if basename.endswith('.gz'):
        basename = basename[:-3]
    base, ext = os.path.splitext(basename)
    output_name = f"{base}{suffix}{ext}"
    if gzip_output:
        output_name += ".gz"
    return os.path.join(output_folder, output_name)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enrich ICMP stats CSV files with payload analysis information."
    )
    parser.add_argument(
        "-i", "--input-dir",
        required=True,
        help="Input directory containing CSV files to process."
    )
    parser.add_argument(
        "-o", "--output-dir",
        required=True,
        help="Output directory where enriched files will be saved."
    )
    parser.add_argument(
        "-g", "--gzip",
        action="store_true",
        help="If set, output files will NOT be compressed with gzip."
    )

    return parser.parse_args()


def collect_input_files(input_paths):
    """Collect all CSV files from input paths (files or directories)."""
    all_files = []
    for input_path in input_paths:
        p = Path(input_path)
        if p.is_dir():
            # If it's a directory, get all CSV files matching pattern _1.csv or _1.csv.gz or containing _1_
            files = sorted([
                fp for fp in p.iterdir()
                if fp.is_file() and (fp.name.endswith("_1.csv") or fp.name.endswith("_1.csv.gz") or
                                     ('_1_' in fp.name and fp.name.endswith(".csv")) or
                                     ('_1_' in fp.name and fp.name.endswith(".csv.gz")))
            ])
            all_files.extend(files)
        elif p.is_file():
            # If it's a file, add it directly if it matches the pattern
            if p.name.endswith("_1.csv") or p.name.endswith("_1.csv.gz") or \
               ('_1_' in p.name and (p.name.endswith(".csv") or p.name.endswith(".csv.gz"))):
                all_files.append(p)

    return sorted(all_files)


def main():
    args = parse_args()
    dir_input = args.input_dir
    dir_output = args.output_dir
    gzip_output = not args.gzip  # If -g is set, do NOT compress

    # ## Load the dataset
    # Load the dataset using the icmp files form the specified directory.
    all_files = collect_input_files([dir_input])

    columns_out_icmp = [
        "timestamp", "ip_version", "ip_orig_tos", "ip_tos", "ip_prec", "ip_dscp",
        "ip_enc", "ip_len", "ip_id", "ip_ttl", "ip_chksum", "ip_src", "ip_dst",
        "ip_options", "icmp_type", "icmp_code", "icmp_id", "icmp_seq",
        "icmp_chksum", "payload_hex", "key", "IBR_info",
    ]

    # Create the output directory if it doesn't exist
    os.makedirs(dir_output, exist_ok=True)

    # Use a loop to read, process, enrich and save each file
    for file in all_files:
        print(f"Processing file: {file}")
        if str(file).endswith('.csv'):
            df = pd.read_csv(file, sep=';', names=columns_out_icmp)
        elif str(file).endswith('.csv.gz'):
            df = pd.read_csv(file, compression='gzip', sep=';', names=columns_out_icmp)
        else:
            print(f"Unsupported file format: {file}")
            continue

        # Further processing and enrichment steps would go here
        output_filename = create_output_filename(file, dir_output, suffix="_enriched", gzip_output=gzip_output)

        # Convert the IBR_info column from JSON string to actual dictionary
        df['IBR_info'] = df['IBR_info'].apply(json.loads)

        # Update the dataframe with enrichment functions
        df = include_ip_hex_columns(df)
        df = include_flag_address_in_payload_columns(df)
        df = include_payload_length_column(df)
        print_ip_address_in_payload_stats(file, df)
        df = copy_info_to_ibrjson(df)
        df = remove_temp_columns(df)

        # Save the enriched dataframe to a new CSV file
        print(f"Enriched data will be saved to: {output_filename}")
        if gzip_output:
            df.to_csv(output_filename, sep=';', index=False, compression='gzip')
        else:
            df.to_csv(output_filename, sep=';', index=False)


if __name__ == "__main__":
    main()
