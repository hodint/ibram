# Column definitions for different protocols

# Define the dictionary for IP types with type annotations
ip_types = {
    'ip_version': str,
    'ip_ihl': int,
    'ip_orig_tos': str,
    'ip_tos': str,
    'ip_prec': str,
    'ip_dscp': str,
    'ip_enc': str,
    'ip_len': int,
    'ip_id': str,
    'ip_orig_flags': str,
    'ip_flag_MF': str,
    'ip_flag_DF': str,
    'ip_flag_Error': str,
    'ip_frag': int,
    'ip_ttl': int,
    'ip_proto': int,
    'ip_chksum': str,
    'ip_src': str,
    'ip_dst': str,
    'ip_options': str
}

icmp_types = {
    'icmp_type': str,
    'icmp_code': str,
    'icmp_id': str,
    'icmp_seq': str,
    'icmp_chksum': str
}

udp_types = {
    'udp_sport': str,
    'udp_dport': str,
    'udp_len': str,
    'udp_chksum': str
}

tcp_types = {
    'tcp_sport': str,
    'tcp_dport': str,
    'tcp_seq': str,
    'tcp_ack': str,
    'tcp_dataofs': str,
    'tcp_reserved': str,
    'tcp_orig_flags': str,
    'tcp_CWR': str,
    'tcp_ACK': str,
    'tcp_PSH': str,
    'tcp_RST': str,
    'tcp_SYN': str,
    'tcp_URG': str,
    'tcp_FIN': str,
    'tcp_ECE': str,
    'tcp_NS': str,
    'tcp_other_flags': str,
    'tcp_window': str,
    'tcp_chksum': str,
    'tcp_urgptr': str,
    'tcp_options': str
}

tail_types = {
    'payload_hex': str,
    'key': str,
    'IBR_info': str
}


# Columns to keep for each protocol
cols_ip = list(ip_types.keys())
cols_icmp = list(icmp_types.keys())
cols_tcp = list(tcp_types.keys())
cols_udp = list(udp_types.keys())
cols_tail = list(tail_types.keys())

columns_out_icmp = [
    "timestamp",
    *cols_ip,
    *cols_icmp,
    *cols_tail
]

columns_out_tcp = [
    "timestamp",
    *cols_ip,
    *cols_tcp,
    *cols_tail
]

columns_out_udp = [
    "timestamp",
    *cols_ip,
    *cols_udp,
    *cols_tail
]

columns_out_otros = [
    "timestamp",
    *cols_ip,
    *cols_tail
]

# Columns order
col_order = [
    "timestamp",
    *cols_ip,
    *cols_icmp,
    *cols_udp,
    *cols_tcp,
    *cols_tail
]

# Columns removed if the reassembly was successful
cols_remove_reassembly_success = [
    'ip_frag', 'ip_flag_MF', 'ip_ihl', 'ip_proto', 'ip_orig_flags',
    'ip_flag_DF', 'ip_flag_Error'
]

# Definition of column types for CSV file import
col_type_csv_import = {
    'timestamp': str,
    # IP
    **ip_types,
    # ICMP
    **icmp_types,
    # UDP
    **udp_types,
    # TCP
    **tcp_types,
    # Others
    **tail_types
}
