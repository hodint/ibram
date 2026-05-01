import argparse
import re
import pandas as pd
from pathlib import Path
from collections import defaultdict
import json


# File pattern to extract date from filename
FILE_PATTERN = re.compile(r".*_(\d{8})_.*\.csv$")


def get_files(inputs):
    """
    inputs could be:
    - a string with a file or directory
    - a list of strings
    - mixed Paths

    Returns a list of Paths to valid CSV files.
    """
    if isinstance(inputs, (str, Path)):
        inputs = [inputs]

    result = set()  # avoid duplicates

    for item in inputs:
        p = Path(item)

        # If it's a directory → search for CSV files that match your pattern
        if p.is_dir():
            for f in p.glob("*.csv"):
                if FILE_PATTERN.match(f.name):
                    result.add(f.resolve())

        # If it's a file → check if it matches
        elif p.is_file():
            if FILE_PATTERN.match(p.name):
                result.add(p.resolve())
            else:
                print(f"Skipped (pattern does not match): {p}")

        # If it does not exist
        else:
            print(f"Warning: {p} does not exists.")

    return sorted(result)


def extract_day(filename):
    """Extracts the day (YYYYMMDD) from the filename."""
    m = FILE_PATTERN.match(filename)
    if not m:
        return None
    return m.group(1)


def read_file(filepath):
    """
    Reads a CSV file and returns a pandas DataFrame.
    """
    df = pd.read_csv(filepath, sep=';', header=None, dtype=str, engine='python')
    return df


MODIFIED_FIELDS = [
    'timestamp',
    'ip_version', 'ip_ihl', 'ip_orig_tos', 'ip_tos',
    'ip_prec',
    'ip_dscp',
    'ip_enc', 'ip_len', 'ip_id', 'ip_orig_flags', 'ip_flag_MF', 'ip_flag_DF',
    'ip_flag_Error', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_src',
    'ip_dst',
    'ip_options',
    'icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq', 'icmp_chksum',
    'udp_sport', 'udp_dport', 'udp_len', 'udp_chksum',
    'tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack',
    'tcp_dataofs', 'tcp_reserved', 'tcp_orig_flags', 'tcp_CWR',
    'tcp_ACK_flag', 'tcp_PSH', 'tcp_RST', 'tcp_SYN', 'tcp_URG', 'tcp_FIN',
    'tcp_ECE', 'tcp_NS', 'tcp_other_flags', 'tcp_window',
    'tcp_chksum', 'tcp_urgptr', 'tcp_options', 'payload_hex',
    'key', 'IBR_info']


def process_ip_proto(df, day, results_proto):
    """
    Processes the 'ip_proto' column in the DataFrame and counts occurrences of each protocol.
    Updates results_proto in place.
    """
    # Most used protocols
    column = MODIFIED_FIELDS.index('ip_proto')
    wk_df = pd.to_numeric(df[column], errors='coerce')

    counts = wk_df.value_counts()

    for proto, count in counts.items():
        proto = int(proto)
        results_proto[day][proto] += int(count)


def process_ip_src(df, day, results_ip_src):
    """
    Processes the 'ip_src' column in the DataFrame and counts occurrences of each source IP.
    Updates results_ip_src in place.
    """
    # Different IP sources
    column = MODIFIED_FIELDS.index('ip_src')
    wk_df = df[column]

    counts = wk_df.value_counts()

    for ip_src, count in counts.items():
        results_ip_src[day][ip_src] += int(count)


def process_ip_dst(df, day, results_ip_dst):
    """
    Processes the 'ip_dst' column in the DataFrame and counts occurrences of each destination IP.
    Updates results_ip_dst in place.
    """
    # Different IP destinations
    column = MODIFIED_FIELDS.index('ip_dst')
    wk_df = df[column]

    counts = wk_df.value_counts()

    for ip_dst, count in counts.items():
        results_ip_dst[day][ip_dst] += int(count)


def process_ip_5min(df, day, results_ip_5min):
    """
    Processes traffic in 5-minute intervals.
    Stores the timestamp and the number of packets received in each 5-minute slot.
    Updates results_ip_5min in place.
    """
    wk_df = df[[MODIFIED_FIELDS.index('timestamp')]].copy()
    wk_df.columns = ['timestamp']
    wk_df['timestamp'] = pd.to_datetime(pd.to_numeric(wk_df['timestamp'], errors='coerce'), unit='s')

    # Create 5-minute blocks
    wk_df['time_bucket'] = wk_df['timestamp'].dt.floor('5min')

    # Count packets per 5-minute block
    for time_bucket, count in wk_df.groupby('time_bucket').size().items():
        time_key = time_bucket.strftime('%Y-%m-%d %H:%M:%S')
        results_ip_5min[day][time_key] = count


def process_udp_dports(df, day, results_udp_ports):
    """
    Processes 'udp_dport' columns in the DataFrame and counts occurrences of each UDP port.
    Updates results_udp_ports in place.
    """
    # Filter the udp protocol
    wk_df = df.copy()
    tcp_col = MODIFIED_FIELDS.index('ip_proto')
    wk_df = wk_df[wk_df[tcp_col] == '17']

    column = MODIFIED_FIELDS.index('udp_dport')
    wk_df = pd.to_numeric(wk_df[column], errors='coerce')

    counts = wk_df.value_counts()

    for port, count in counts.items():
        port = int(port)
        results_udp_ports[day][port] += int(count)


def process_tcp_dports(df, day, results_tcp_ports):
    """
    Processes 'tcp_dport' column in the DataFrame and counts occurrences of each TCP destination port.
    Updates results_tcp_ports in place.
    """
    # Filter the TCP protocol (ip_proto == 6)
    wk_df = df.copy()
    proto_col = MODIFIED_FIELDS.index('ip_proto')
    wk_df = wk_df[wk_df[proto_col] == '6']

    column = MODIFIED_FIELDS.index('tcp_dport')
    wk_df = pd.to_numeric(wk_df[column], errors='coerce')

    counts = wk_df.value_counts()

    for port, count in counts.items():
        port = int(port)
        results_tcp_ports[day][port] += int(count)


def process_icmp_types(df, day, results_icmp_types):
    """
    Processes 'icmp_type' column in the DataFrame and counts occurrences of each ICMP type.
    Updates results_icmp_types in place.
    """
    # Filter the ICMP protocol (ip_proto == 1)
    wk_df = df.copy()
    proto_col = MODIFIED_FIELDS.index('ip_proto')
    wk_df = wk_df[wk_df[proto_col] == '1']

    column = MODIFIED_FIELDS.index('icmp_type')
    wk_df = pd.to_numeric(wk_df[column], errors='coerce')

    counts = wk_df.value_counts()

    for icmp_type, count in counts.items():
        icmp_type = int(icmp_type)
        results_icmp_types[day][icmp_type] += int(count)


def process_icmp_types_and_codes(df, day, results_icmp_types_and_codes):
    """
    Processes 'icmp_type' and 'icmp_code' columns in the DataFrame and counts occurrences of each ICMP type and code combination.
    Updates results_icmp_types_and_codes in place.
    """
    type_column = MODIFIED_FIELDS.index('icmp_type')
    code_column = MODIFIED_FIELDS.index('icmp_code')

    # Filter the icmp protocol
    wk_df = df.copy()
    tcp_col = MODIFIED_FIELDS.index('ip_proto')
    wk_df = wk_df[wk_df[tcp_col] == '1']

    wk_df = wk_df[[type_column, code_column]].copy()
    wk_df.columns = ['icmp_type', 'icmp_code']
    wk_df['icmp_type'] = pd.to_numeric(wk_df['icmp_type'], errors='coerce')
    wk_df['icmp_code'] = pd.to_numeric(wk_df['icmp_code'], errors='coerce')

    # Remove rows with NaN values
    wk_df = wk_df.dropna()

    # Create a combined key of type and code
    wk_df['type_code'] = wk_df.apply(lambda row: (int(row['icmp_type']), int(row['icmp_code'])), axis=1)

    counts = wk_df['type_code'].value_counts()

    for (icmp_type, icmp_code), count in counts.items():
        results_icmp_types_and_codes[day][(icmp_type, icmp_code)] += int(count)


def process_tcp_flags(df, day, results_tcp_flags):
    """
    Processes TCP flag columns in the DataFrame and counts occurrences of each flag combination.
    Interpreta correctamente valores True/False (bool reales o cadenas) y construye
    combinaciones de flags. Incluye tcp_other_flags cuando existe.
    Actualiza results_tcp_flags in place.
    """
    col_tcp_cwr = MODIFIED_FIELDS.index('tcp_CWR')
    col_tcp_ack = MODIFIED_FIELDS.index('tcp_ACK_flag')
    col_tcp_psh = MODIFIED_FIELDS.index('tcp_PSH')
    col_tcp_rst = MODIFIED_FIELDS.index('tcp_RST')
    col_tcp_syn = MODIFIED_FIELDS.index('tcp_SYN')
    col_tcp_urg = MODIFIED_FIELDS.index('tcp_URG')
    col_tcp_fin = MODIFIED_FIELDS.index('tcp_FIN')
    col_tcp_ece = MODIFIED_FIELDS.index('tcp_ECE')
    col_tcp_ns  = MODIFIED_FIELDS.index('tcp_NS')
    col_tcp_other = MODIFIED_FIELDS.index('tcp_other_flags')

    # Filter the tcp protocol
    wk_df = df.copy()
    tcp_col = MODIFIED_FIELDS.index('ip_proto')
    wk_df = wk_df[wk_df[tcp_col] == '6']
    # print(wk_df)

    wk_df = wk_df[[col_tcp_cwr, col_tcp_ack, col_tcp_psh, col_tcp_rst, col_tcp_syn, col_tcp_urg,
                col_tcp_fin, col_tcp_ece, col_tcp_ns, col_tcp_other]].copy()
    wk_df.columns = ['CWR', 'ACK', 'PSH', 'RST', 'SYN', 'URG', 'FIN', 'ECE', 'NS', 'OTHER']

    def to_bool_int(val):
        if isinstance(val, bool):
            return 1 if val else 0
        if pd.isna(val):
            return 0
        s = str(val).strip().lower()
        if s in ('1','true','t','yes','y'): return 1
        if s in ('0','false','f','no','n',''): return 0
        try:
            num = float(s)
            return 1 if num != 0 else 0
        except ValueError:
            return 0

    # Convert flag columns to 0/1 while preserving True/False semantics
    for col in ['CWR','ACK','PSH','RST','SYN','URG','FIN','ECE','NS']:
        wk_df[col] = wk_df[col].map(to_bool_int)

    def build_flag_combo(row):
        flags = []
        if row['SYN']: flags.append('SYN')
        if row['ACK']: flags.append('ACK')
        if row['FIN']: flags.append('FIN')
        if row['RST']: flags.append('RST')
        if row['PSH']: flags.append('PSH')
        if row['URG']: flags.append('URG')
        if row['ECE']: flags.append('ECE')
        if row['CWR']: flags.append('CWR')
        if row['NS']:  flags.append('NS')
        other = str(row['OTHER']).strip()
        if other and other not in ('0','', 'nan', 'None'):  # attach other flags descriptor
            flags.append(f'OTHER:{other}')
        return ','.join(flags) if flags else 'NONE'

    wk_df['flag_combination'] = wk_df.apply(build_flag_combo, axis=1)

    for combo, count in wk_df['flag_combination'].value_counts().items():
        results_tcp_flags[day][combo] += int(count)


def counter_protocol(files):
    results_proto = defaultdict(lambda: defaultdict(int))
    results_ip_src = defaultdict(lambda: defaultdict(int))
    results_ip_dst = defaultdict(lambda: defaultdict(int))
    results_ip_5min = defaultdict(lambda: defaultdict(int))
    results_udp_dports = defaultdict(lambda: defaultdict(int))
    results_tcp_dports = defaultdict(lambda: defaultdict(int))
    results_icmp_types = defaultdict(lambda: defaultdict(int))
    results_icmp_types_and_codes = defaultdict(lambda: defaultdict(int))
    results_tcp_flags = defaultdict(lambda: defaultdict(int))

    for f in files:
        print(f"Processing: {f}")
        day = extract_day(f.name)
        if not day:
            print(f"Skipped (no match): {f}")
            continue

        try:
            df = read_file(f)

            # Count protocols in the file, results_proto is updated in place
            process_ip_proto(df, day, results_proto)

            # Count different IP sources, results_ip_src is updated in place
            process_ip_src(df, day, results_ip_src)

            # Count different IP destinations, results_ip_dst is updated in place
            process_ip_dst(df, day, results_ip_dst)

            # Count traffic every 5 minutes, results_ip_5min is updated in place
            process_ip_5min(df, day, results_ip_5min)

            # Count UDP ports, results_udp_ports is updated in place
            process_udp_dports(df, day, results_udp_dports)

            # Count TCP ports, results_tcp_ports is updated in place
            process_tcp_dports(df, day, results_tcp_dports)

            # Count ICMP types, results_icmp_types is updated in place
            process_icmp_types(df, day, results_icmp_types)

            # Count ICMP types and codes, results_icmp_types_and_codes is updated in place
            process_icmp_types_and_codes(df, day, results_icmp_types_and_codes)

            # Count TCP flags, results_tcp_flags is updated in place
            process_tcp_flags(df, day, results_tcp_flags)
        except Exception as e:
            print(f"Error processing {f}: {e}")

    # Convert defaultdict to regular dict for cleaner output
    dict_results = {
        'ip_proto': {day: dict(proto_counts) for day, proto_counts in results_proto.items()},
        'ip_src': {day: dict(ip_counts) for day, ip_counts in results_ip_src.items()},
        'ip_dst': {day: dict(ip_counts) for day, ip_counts in results_ip_dst.items()},
        'ip_5min': {day: dict(time_counts) for day, time_counts in results_ip_5min.items()},
        'udp_dports': {day: dict(port_counts) for day, port_counts in results_udp_dports.items()},
        'tcp_dports': {day: dict(port_counts) for day, port_counts in results_tcp_dports.items()},
        'icmp_types': {day: dict(type_counts) for day, type_counts in results_icmp_types.items()},
        'icmp_types_and_codes': {day: dict(type_code_counts) for day, type_code_counts in results_icmp_types_and_codes.items()},
        'tcp_flags': {day: dict(flag_counts) for day, flag_counts in results_tcp_flags.items()},
    }

    return dict_results


def print_results(results):
    print("\n=== FINAL RESULTS ===")
    for day in sorted(results):
        print(f"{day}: {dict(results[day])}")


def aggregate_results(results):
    """
    Aggregates all values across all days for both ip_proto and ip_src.
    Returns a dictionary with aggregated counts.
    """
    aggregated = {}

    for key, day_data in results.items():
        totals = defaultdict(int)

        for day, counts in day_data.items():
            for item, count in counts.items():
                totals[item] += count

        # Convert to regular dict and sort by count (descending)
        aggregated[key] = dict(sorted(totals.items(), key=lambda x: x[1], reverse=True))
    return aggregated


def save_results_to_json(results, output_file):
    """
    Save the results dictionary to a JSON file.
    Handles tuple keys by converting them to strings.
    """
    serializable_results = {}

    for day, counts in results.items():
        day_data = {}
        for key, value in counts.items():
            # Convert tuples to strings for JSON serialization
            if isinstance(key, tuple):
                day_data[str(key)] = value
            else:
                day_data[key] = value
        serializable_results[day] = day_data

    with open(output_file, "w") as f:
        json.dump(serializable_results, f, indent=2)

    print(f"Results saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Count protocols per day in darknet CSV files")
    parser.add_argument("input_folder", help="Input directoryy or files")
    parser.add_argument("output_folder", help="Output directory for results")
    args = parser.parse_args()

    input_folder = Path(args.input_folder)
    output_folder = Path(args.output_folder)

    # Get list of files to process
    files = get_files(input_folder)
    print(f"Found {len(files)} files to process.")

    if not files:
        print("No valid files found.")
        return

    # Process files and get results
    results = counter_protocol(files)
    for key, _ in results.items():
        print(f"\nResults for {key}:")

    # Save results to JSON
    save_results_to_json(results['ip_proto'], output_folder / "protocol_counts.json")
    save_results_to_json(results['ip_src'], output_folder / "ip_src_counts.json")
    save_results_to_json(results['ip_dst'], output_folder / "ip_dst_counts.json")
    save_results_to_json(results['ip_5min'], output_folder / "ip_5min_counts.json")
    save_results_to_json(results['udp_dports'], output_folder / "udp_dport_counts.json")
    save_results_to_json(results['tcp_dports'], output_folder / "tcp_dport_counts.json")
    save_results_to_json(results['tcp_flags'], output_folder / "tcp_flag_counts.json")
    save_results_to_json(results['icmp_types'], output_folder / "icmp_type_counts.json")
    save_results_to_json(results['icmp_types_and_codes'], output_folder / "icmp_types_and_codes_counts.json")


if __name__ == "__main__":
    main()
