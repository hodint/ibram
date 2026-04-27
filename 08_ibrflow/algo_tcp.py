"""
TCP Traffic Classification Module

This module provides functions to detect and classify network scanning tools
based on their TCP packet fingerprints: Mirai, ZMap, MasScan, Hajime, and Unicorn.
"""

from tqdm import tqdm


def add_mirai_column(df):
    """
    Detect Mirai botnet traffic.

    Mirai encodes the destination IP address in the TCP sequence number.
    """
    df['mirai_id'] = df['tcp_seq'].apply(lambda x: '.'.join(str(x) for x in [x for x in bytearray.fromhex('{:08x}'.format(int(x)))]))

    # Get rows where mirai_id equals destination IP and TCP SYN flag is set
    df['mirai'] = (df['mirai_id'] == df['ip_dst']) & (df['tcp_SYN'] == 'True')

    # Delete temporary column
    del df['mirai_id']

    return df


def add_zmap_column(df):
    """
    Detect ZMap scanner traffic.

    ZMap uses a fixed IP ID value of 54321 with SYN packets.
    """
    df['zmap'] = (df['ip_id'] == '54321') & (df['tcp_SYN'] == 'True')
    return df


def ip_to_int(ip):
    """
    Convert an IP address string to its integer representation.

    Args:
        ip: IP address string (e.g., "192.168.1.1")

    Returns:
        Integer representation of the IP address
    """
    try:
        parts = str(ip).split('.')
        return int.from_bytes([int(p) for p in parts], byteorder='big')
    except:
        return 0


def add_masscan_column(df):
    """
    Detect MasScan scanner traffic.

    MasScan calculates IP ID as: (dst_ip XOR dst_port XOR seq_num) & 0xFFFF
    """
    # Convert ip_dst column to integer
    df['ip_dst_int'] = df['ip_dst'].apply(ip_to_int)

    # Ensure tcp_dport and tcp_seq are integers
    df['tcp_dport'] = df['tcp_dport'].astype(int)
    df['tcp_seq'] = df['tcp_seq'].astype(int)

    # Calculate expected IP ID and reduce to 16 bits
    df['calculated_ipid'] = (df['ip_dst_int'] ^ df['tcp_dport'] ^ df['tcp_seq']) & 0xFFFF

    # Convert type for comparison
    df['calculated_ipid'] = df['calculated_ipid'].astype(str)

    # Comparison
    df['masscan'] = df['ip_id'] == df['calculated_ipid']

    # Clean up temporary columns
    df = df.drop(columns=['ip_dst_int', 'calculated_ipid'])

    return df


def add_hajime_column(df):
    """
    Detect Hajime botnet traffic.

    Hajime uses a fixed TCP window size of 14600 with SYN packets.
    To confirm Hajime (vs possible Hajime), the source IP must connect
    to multiple destination ports with the same TCP window of 14600.
    """
    # Filter traffic with TCP window 14600 and SYN flag set
    hajime_df = df[(df['tcp_window'] == '14600') & (df['tcp_SYN'] == 'True')]
    df['hajime_possible'] = (df['tcp_window'] == '14600') & (df['tcp_SYN'] == 'True')

    """
    The difference between confirmed Hajime and possible Hajime is that for confirmed Hajime,
    the source IP must connect to multiple destination ports with the same TCP window of 14600.
    If it only connects to one destination port, it's marked as possible Hajime.
    """
    # Group by source IP and destination port
    ip_port_counts = hajime_df.groupby(['ip_src', 'tcp_dport']).size().reset_index(name='count')

    # Identify IPs connecting to multiple ports
    ip_multiple_ports = ip_port_counts.groupby('ip_src').size()
    ip_multiple_ports = ip_multiple_ports[ip_multiple_ports > 2]  # At least two different ports with same tcp_window
    confirmed_hajime_ips = ip_multiple_ports.index.tolist()

    # Mark Hajime traffic based on identified IPs
    df['hajime'] = df['ip_src'].isin(confirmed_hajime_ips)

    return df


def add_unicorn_column(df):
    """
    Detect Unicorn scanner traffic.

    Unicorn encodes source and destination host information in the TCP sequence number.
    Two packets are from Unicorn if they satisfy:
    SeqNum1 ⊕ SeqNum2 = destIP1 ⊕ destIP2 ⊕ srcPort1 ⊕ srcPort2 ⊕ ((destPort1 ⊕ destPort2) << 16)

    Args:
        df: DataFrame with columns ip_src, ip_dst, tcp_seq, tcp_sport, tcp_dport

    Returns:
        DataFrame with additional 'unicorn' column (bool)
    """
    df = df.copy()
    df['unicorn'] = False

    # Prepare numeric columns
    df['_ip_dst_int'] = df['ip_dst'].apply(ip_to_int)
    df['_tcp_seq_int'] = df['tcp_seq'].astype(int)
    df['_tcp_sport_int'] = df['tcp_sport'].astype(int)
    df['_tcp_dport_int'] = df['tcp_dport'].astype(int)

    # Group by ip_src and search for pairs that satisfy the relationship
    unicorn_ips = set()

    for ip_src, group in df.groupby('ip_src'):
        if len(group) < 2:
            continue

        # Take first 1000 if group is too large (optimization)
        if len(group) > 1000:
            group = group.head(1000)

        rows = group[['_tcp_seq_int', '_ip_dst_int', '_tcp_sport_int', '_tcp_dport_int']].values

        # Compare packet pairs
        found = False
        for i in range(min(len(rows), 100)):  # Limit comparisons
            for j in range(i + 1, min(len(rows), 100)):
                seq1, dst1, sport1, dport1 = rows[i]
                seq2, dst2, sport2, dport2 = rows[j]

                left_side = int(seq1) ^ int(seq2)
                right_side = (int(dst1) ^ int(dst2)) ^ (int(sport1) ^ int(sport2)) ^ ((int(dport1) ^ int(dport2)) << 16)

                # Compare with 32-bit mask
                # if (left_side & 0xFFFFFFFF) == (right_side & 0xFFFFFFFF):
                if left_side == right_side:
                    unicorn_ips.add(ip_src)
                    found = True
                    break
            if found:
                break

    # Mark all rows from IPs identified as Unicorn
    df['unicorn'] = df['ip_src'].isin(unicorn_ips)

    # Clean up temporary columns
    df = df.drop(columns=['_ip_dst_int', '_tcp_seq_int', '_tcp_sport_int', '_tcp_dport_int'])

    return df


def unicorn_calculator(df, idx1, idx2):
    """
    Calculate if two packets satisfy the Unicorn detection formula.

    Args:
        df: DataFrame containing packet data
        idx1: Index of first packet
        idx2: Index of second packet

    Returns:
        True if packets match Unicorn pattern, False otherwise
    """
    seq1 = int(df.loc[idx1, 'tcp_seq'])
    seq2 = int(df.loc[idx2, 'tcp_seq'])

    dst_ip1 = ip_to_int(df.loc[idx1, 'ip_dst'])
    dst_ip2 = ip_to_int(df.loc[idx2, 'ip_dst'])

    src_port1 = int(df.loc[idx1, 'tcp_sport'])
    src_port2 = int(df.loc[idx2, 'tcp_sport'])

    dst_port1 = int(df.loc[idx1, 'tcp_dport'])
    dst_port2 = int(df.loc[idx2, 'tcp_dport'])

    # Calculate both sides of the equation
    left_side = seq1 ^ seq2
    right_side = (dst_ip1 ^ dst_ip2 ^
                  src_port1 ^ src_port2 ^
                  ((dst_port1 ^ dst_port2) << 16))

    # If match, return True
    found = False
    if (left_side & 0xFFFFFFFF) == (right_side & 0xFFFFFFFF):
        found = True

    return found

def add_unicorn_column_2(df, max_comparisons=10):
    """
    Detect Unicorn traffic in an optimized way.

    For each unique source IP:
    - Filter records for that IP
    - Compare up to max_comparisons packet pairs
    - If any pair matches, mark ALL packets from that IP as Unicorn and move to next

    Formula: SeqNum1 ⊕ SeqNum2 = destIP1 ⊕ destIP2 ⊕ srcPort1 ⊕ srcPort2 ⊕ ((destPort1 ⊕ destPort2) << 16)

    Args:
        df: DataFrame with columns ip_src, ip_dst, tcp_seq, tcp_sport, tcp_dport
        max_comparisons: Maximum number of comparisons per IP (default: 10)

    Returns:
        DataFrame with additional 'unicorn2' column (bool)
    """
    df = df.copy()

    # Get list of unique source IPs
    unique_ips = df['ip_src'].unique()
    unicorn_ips = set()

    for src_ip in tqdm(unique_ips, desc="Processing IPs (unicorn2)"):
        # Filter dataframe by source IP
        df_ip = df[df['ip_src'] == src_ip]
        if len(df_ip) < 2:
            continue

        # Get indices to compare
        indices = df_ip.index.tolist()
        n = len(indices)

        # Limit comparisons
        comparisons_done = 0
        found = False

        for i in range(min(n, max_comparisons + 1)):
            if found:
                break
            for j in range(i + 1, min(n, max_comparisons + 1)):
                if comparisons_done >= max_comparisons:
                    break
                try:
                    # Check if the two indices satisfy the condition
                    found = unicorn_calculator(df, indices[i], indices[j])
                    comparisons_done += 1

                    # If match, mark IP as Unicorn and move to next
                    if found:
                        unicorn_ips.add(src_ip)
                        break

                except (ValueError, TypeError, KeyError):
                    continue

            if comparisons_done >= max_comparisons:
                break

    # Mark all rows from IPs identified as Unicorn
    df['unicorn2'] = df['ip_src'].isin(unicorn_ips)

    print(f"IPs identified as Unicorn: {len(unicorn_ips)}")

    return df
