#!/usr/bin/env python
# coding: utf-8


import os
import shutil
import pandas as pd
import logging
import time
import argparse
import glob
import json
import gzip
import numpy as np
from pca_file_load import load_pcap_csv_gz
import coldefinitions as coldef


def _to_jsonable(obj):
    """Convert pandas/NumPy types within obj to Python-native types for json.dumps."""
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [ _to_jsonable(v) for v in obj ]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, pd.Timestamp):
        return float(obj.timestamp())
    if isinstance(obj, np.datetime64):
        return float(pd.Timestamp(obj).timestamp())
    if obj is pd.NA:
        return None
    try:
        if pd.isna(obj):
            print("pd.isna caught", obj)
            return None
    except Exception:
        print("pd.isna exception", obj)
    return obj


def split_fragmented_datasets(df):
    """
    Function that splits a dataframe in two, one with fragmented packets and one with non-fragmented packets.
    param df: DataFrame with all packets
    return: Two DataFrames, one with the fragmented packets and one with the non-fragmented ones
    """
    # if dataframe is empty, return two empty dataframes
    if df.empty:
        return pd.DataFrame(), pd.DataFrame()

    # First I extract in a dataframe the packages that are not fragmented
    df_no_frag = df[(df['ip_frag'] == 0) & (df['ip_flag_MF'] != 'True')]

    # I delete the view and create a copy of the dataframe
    df_no_frag = df_no_frag.copy()

    # Fragmented packets
    # I extract packets that have fragmentation
    df_frag = df[(df['ip_frag'] != 0) | (df['ip_flag_MF'] == 'True')]
    df_frag = df_frag.copy()

    # Free memory
    del df

    # Return the dataframes
    return df_frag, df_no_frag


def get_first_fragmented_packet(df):
    """
    Function that gets the first fragmented packet of each fragmentation.
    :param df: DataFrame with fragmented packets
    :return: DataFrame with the first packet of each fragmentation
    """
    # Now, I get the first packets from the framgentation
    dffp = df[df['ip_frag'] == 0]

    # I create a dataframe with the first fragmentation records,
    # with the fields I will use later to search for
    dffps = dffp[['ip_src', 'ip_dst', 'ip_id', 'ip_proto', 'timestamp', 'key']]
    dffps = dffps.copy()

    # I remove duplicates of df_frag_first_search and return it. (Should not be dups)
    dffps = dffps.drop_duplicates()
    return dffp


def get_current_payload_bytes(df_sorted, i):
    """
    This function gets the payload bytes of the current fragment
    :param df_sorted: DataFrame with the fragments sorted by ip_frag
    :param i: Index of the current fragment
    :return: Payload bytes of the current fragment
    """
    previous_ip_ihl = df_sorted['ip_ihl'].iloc[i-1]
    previous_ip_len = df_sorted['ip_len'].iloc[i-1]
    # header_bytes = previous_ip_ihl * 4  # Header lenght in bits
    header_bytes = previous_ip_ihl
    payload_len = previous_ip_len - header_bytes  # Payload length in bits
    payload_bytes = payload_len // 8  # Payload length in bytes
    return payload_bytes


def get_fragments_count(df):
    """
    This function gets the number of fragments
    :param df: DataFrame with the fragments
    :return: DataFrame without duplicated fragments and number of fragments
    """
    # Count the number of fragments
    fragment_count = len(df)

    # Remove duplicates (should be none after remove_duplicates_fragments)
    df = df.drop_duplicates()

    return df, fragment_count


def packet_reassembly(df, resultado):
    """
    This function reassembles the packets
    :param df: DataFrame with the fragments
    :param resultado: Dictionary with the results
    :return: List with the reassembled payloads and the dictionary with the results
    """
    # Concatenate payloads and check for missing fragments
    payloads_concat = []
    new_payload_len = 0

    # Check duplicates and concatenate payload if they are the same
    df_sorted = df.sort_values(by=['ip_frag']).reset_index(drop=True)

    """
    A fast, not perfect, concatenation algorithm is performed,
    hoping that in the timestamp + variation period no two IDs are the same.
    The following loop can be improved, by selecting if there are several
    fragments with the same IDs
    """
    # Check missing fragments
    for i in range(1, len(df_sorted)):
        # Get the payload bytes for current fragment
        payload_bytes = get_current_payload_bytes(df_sorted, i)

        # Fragment values
        previous_frag_end = df_sorted['ip_frag'].iloc[i-1] + payload_bytes
        current_frag_start = df_sorted['ip_frag'].iloc[i]

        if current_frag_start != previous_frag_end:
            # There are missing fragments
            missing_start = previous_frag_end
            missing_end = current_frag_start
            resultado['missing'].append((missing_start, missing_end))

        # Append the payload
        payloads_concat.append(df_sorted['payload_hex'].iloc[i-1])
        new_payload_len += df_sorted['ip_len'].iloc[i-1]

        # If we are at the last one, then save it too
        if i == len(df_sorted) - 1:
            payloads_concat.append(df_sorted['payload_hex'].iloc[i])
            new_payload_len += df_sorted['ip_len'].iloc[i]

    # Save the new payload length
    resultado['fragmented_ip_len'] = new_payload_len

    return payloads_concat, resultado


def verify_ip_fragments(df):
    """
    This function gets the values of duplicates, missing fragments and payload
    and returns a dictionary with them.
    The input is the dataframe with the related fragments.
    param df: DataFrame with the related fragments
    return: Dictionary with the values of duplicates,
            missing fragments and payload
    """
    # Initialize the dictionary with the results
    resultado = {
        'fragment_count': 0,
        'missing': [],
        'last_missing': False
    }

    # To concatenate the payloads, all fragments must be included
    df = df[['ip_src', 'ip_dst', 'ip_id', 'ip_proto', 'timestamp',
             'ip_frag', 'ip_ihl', 'ip_len', 'payload_hex', 'ip_flag_MF']]
    df = df.copy()

    df, fragment_count = get_fragments_count(df)
    resultado['fragment_count'] = fragment_count

    # I check if the last fragment is there and if not I indicate that it is missing
    # in the result dictionary and return
    if df['ip_flag_MF'].iloc[-1] == 'True':
        resultado['last_missing'] = True
        return resultado

    """
    At this point, duplicates have already been removed by remove_duplicates_fragments().
    We now process the fragments linearly for reassembly.
    """
    # Payload reassembly
    payloads_concat, resultado = packet_reassembly(df, resultado)

    # If there are missing fragments, I return None
    # I could return payloads_concat, but it is faster.
    if len(resultado['missing']) > 0:
        return resultado

    # Concatenate payload if no fragments are missing
    resultado['payload_hex'] = ''.join(payloads_concat)

    return resultado


def remove_fragments_complete(df_frag_search, df_frag):
    """
    Remove the non-first fragments that were reassembled and report their stats.

    :param df_frag_search: DataFrame with the fragments for the current reassembly group
    :param df_frag: DataFrame with all the fragments
    :return: Tuple (df_frag_updated, ts_min_removed, ts_max_removed, removed_keys)
    """
    df_records_frag = df_frag_search[df_frag_search['ip_frag'] != 0].copy()

    if df_records_frag.empty:
        # Nothing removed
        return df_frag, None, None, []

    # Collect keys and timestamp stats of the removed fragments
    removed_keys = df_records_frag['key'].tolist()
    ts_min_removed = df_records_frag['timestamp'].min()
    ts_max_removed = df_records_frag['timestamp'].max()

    # Drop the removed fragments from the main df
    for k in removed_keys:
        logger.debug(f"Removing fragment {k}")
        df_frag.drop(df_frag.loc[df_frag['key'] == k].index, inplace=True)

    return df_frag, ts_min_removed, ts_max_removed, removed_keys


def get_fragments_group(df_frag, timestamp, time_window, ip_id, ip_src, ip_dst):
    """
    This function gets the fragments that correspond to a packet
    :param df_frag: DataFrame with the fragments
    :param timestamp: Timestamp of the packet
    :param time_window: Time window for the search
    :param ip_id: IP ID of the packet
    :param ip_src: IP source of the packet
    :param ip_dst: IP destination of the packet
    :return: DataFrame with the fragments that correspond to the packet
    """
    # Make sure there is only one first package in the block,
    # otherwise I reduce the time.
    continuar = True
    # Initialize to avoid possibly-unbound warnings
    df_frag_search = df_frag.iloc[0:0].copy()
    while continuar:
        # I get the fragment groups that correspond to this package,
        # with temporally close packets
        df_frag_search = df_frag[
            (df_frag['ip_id'] == ip_id) &
            (df_frag['ip_src'] == ip_src) & (df_frag['ip_dst'] == ip_dst) &
            (df_frag['timestamp'] >= timestamp - pd.to_timedelta(time_window, unit='s')) &
            (df_frag['timestamp'] <= timestamp + pd.to_timedelta(time_window, unit='s'))]

        # The search is done on initial packets, so there is at least one
        len_df_frag_search_ip_frag_0 = len(df_frag_search[df_frag_search['ip_frag'] == 0])
        if len_df_frag_search_ip_frag_0 == 1:
            continuar = False
            continue

        # More than one register, decrement time_window
        time_window -= 1
        logger.debug(f"Attention, more than one record in time_window: {len_df_frag_search_ip_frag_0}, time_window = {time_window}")

        if time_window < 0:
            logger.error(f"More than one registration at the same time: {len_df_frag_search_ip_frag_0}, time_window = {time_window}")
            continuar = False
            continue
    return df_frag_search


def remove_duplicates_fragments(df_frag):
    """
    Function removing duplicated fragments from a dataframe
    :param df_frag: DataFrame with the fragments to be reassembled
    :return: df_frag without duplicated fragments
    """
    # Identify duplicates excluding 'key', 'IBR_info' and 'timestamp'
    cols_for_dup = df_frag.columns.difference(['key', 'IBR_info', 'timestamp'])

    # Group and collect duplicate information
    # For each group, get: count, list of keys, the lowest key
    group_keys = list(cols_for_dup)
    grouped = df_frag.groupby(group_keys, sort=False)

    # Index of the record with the minimum and maximum key per group
    idx_min_key = grouped['key'].idxmin()
    idx_max_key = grouped['key'].idxmax()

    # DataFrames with min_key/max_key and their corresponding timestamps
    minkey_rows = df_frag.loc[idx_min_key, group_keys + ['key', 'timestamp']].copy()
    minkey_rows = minkey_rows.rename(columns={'key': 'min_key', 'timestamp': 'min_key_timestamp'})
    maxkey_rows = df_frag.loc[idx_max_key, group_keys + ['key', 'timestamp']].copy()
    maxkey_rows = maxkey_rows.rename(columns={'key': 'max_key', 'timestamp': 'max_key_timestamp'})

    # Dup count and dup keys
    dup_counts = grouped.agg(
        dup_count=('key', 'size'),
        dup_keys=('key', lambda x: sorted(list(x)))
    ).reset_index()

    # Merge to have per group: dup_count, dup_keys, min_key, min_key_timestamp, max_key, max_key_timestamp
    dup_info = dup_counts.merge(minkey_rows, on=group_keys, how='left').merge(maxkey_rows, on=group_keys, how='left')

    # Filter only the records with the lowest key of each group
    df_with_minkey = df_frag.merge(
        dup_info[group_keys + ['min_key']],
        on=group_keys,
        how='left'
    )
    df_result = df_with_minkey[df_with_minkey['key'] == df_with_minkey['min_key']].copy()
    df_result = df_result.drop(columns=['min_key'])

    # Add duplicate information to IBR_info
    df_result = df_result.merge(
        dup_info[group_keys + ['dup_count', 'dup_keys', 'min_key_timestamp', 'max_key_timestamp']],
        on=group_keys,
        how='left'
    )

    # Update IBR_info only where dup_count > 1
    mask_dups = df_result['dup_count'] > 1
    if mask_dups.any():
        for idx in df_result[mask_dups].index:
            ibr_info = df_result.at[idx, 'IBR_info']
            if isinstance(ibr_info, dict):
                min_ts = df_result.at[idx, 'min_key_timestamp']
                max_ts = df_result.at[idx, 'max_key_timestamp']
                # Convert timestamps to epoch float for JSON safety
                def _to_epoch(ts):
                    if pd.isna(ts):
                        return None
                    try:
                        return convert_to_epoch(ts)
                    except Exception:
                        return float(pd.to_datetime(ts).timestamp()) if pd.notna(ts) else None
                min_ts_epoch = _to_epoch(min_ts)
                max_ts_epoch = _to_epoch(max_ts)

                # Use the kept row's key (min key) as a stable flow id
                kept_key = df_result.at[idx, 'key']
                dup_keys_list = df_result.at[idx, 'dup_keys']
                new_key = f"{kept_key}_dup"

                # Create the IBR flow entry and update the previous IBR_info
                updated_ibr_info, ibr_flow = create_ibr_flow(
                    ibr_flow_id=new_key,
                    ts_start=min_ts_epoch,
                    ts_end=max_ts_epoch,
                    traffic_list=dup_keys_list,
                    action='duplicate_fragments',
                    info={'dup_count': int(df_result.at[idx, 'dup_count'])},
                    previous_ibr_info=ibr_info
                )

                # Update the IBR_info field
                df_result.at[idx, 'IBR_info'] = {
                    **updated_ibr_info,
                    'ibr_flow': ibr_flow
                }

                # Update the key field
                df_result.at[idx, 'key'] = new_key

    # Remove temporary columns
    df_result = df_result.drop(columns=['dup_count', 'dup_keys', 'min_key_timestamp', 'max_key_timestamp'])

    return df_result


def create_ibr_flow(ibr_flow_id, ts_start, ts_end, traffic_list, action, info, previous_ibr_info=None):
    """
    Create an IBR flow structure.
    If previous_ibr_info contains an ibr_flow, it will be nested inside the new flow's info.

    :param ibr_flow_id: Flow ID
    :param ts_start: Start timestamp
    :param ts_end: End timestamp
    :param traffic_list: List of traffic keys
    :param action: Action taken
    :param info: Additional info dictionary
    :param previous_ibr_info: Previous IBR info dictionary (optional, will be copied and modified)
    :return: Tuple (updated_ibr_info, new_ibr_flow)
    """
    # Make a copy to avoid modifying the original
    updated_ibr_info = previous_ibr_info.copy() if previous_ibr_info else {}

    # If there's a previous ibr_flow, nest it inside the new flow's info
    if 'ibr_flow' in updated_ibr_info:
        info = {
            **info,
            'previous_ibr_flow': updated_ibr_info['ibr_flow']
        }
        # Remove the previous ibr_flow from IBR_info
        del updated_ibr_info['ibr_flow']

    # Sort the traffic list
    traffic_list = sorted(traffic_list)

    new_ibr_flow = {
        'ibr_flow_id': ibr_flow_id,
        'ts_start': ts_start,
        'ts_end': ts_end,
        'traffic_list': traffic_list,
        'action': action,
        'info': info
    }

    return updated_ibr_info, new_ibr_flow


def process_fragmented_packets(df_frag, df_reassembled, time_window_gap=60):
    """
    Function reassembling the fragments of a dataframe
    :param df_frag_first: DataFrame with the first fragments of each fragmentation
    :param df_frag: DataFrame with the fragments to be reassembled
    :param df_reassembled: DataFrame with the reassembled fragments
    :param time_window_gap: Temporary window for reassembly
    :return: df_reassembled with reassembled fragments
    """

    # Remove duplicated fragments first
    df_frag = remove_duplicates_fragments(df_frag)

    # At this point, the dataframe is ready to be processed, without duplicates

    # Get the first fragmented packet
    df_frag_first_search = get_first_fragmented_packet(df_frag)

    # Now, for each record in df_frag_first_search, I look for the
    # fragmentation records that correspond to it in the df_frag dataframe
    for _, row in df_frag_first_search.iterrows():
        # Extract search fields
        ip_src = row['ip_src']
        ip_dst = row['ip_dst']
        ip_id = row['ip_id']
        timestamp = row['timestamp']  # Temporary window for reassemblies.

        """
        Get the dataframe with the fragments that correspond to this packet,
        and that its arrival time is inside the time_window.
        Make sure that there is only one first packet in the block,
        if not, I reduce the time
        """
        df_frag_search = get_fragments_group(df_frag, timestamp, time_window_gap, ip_id, ip_src, ip_dst)

        # Now I call a function to reassemble the fragments.
        # The function returns the reassembled payload
        fragments_verified_result = verify_ip_fragments(df_frag_search)

        # If the last fragment is missing, then it cannot be reassembled,
        # Leave it for next time.
        if fragments_verified_result['last_missing']:
            logger.debug(f"Incomplete packet, last fragment missing {row['key']}")
            continue

        """
        If everything went well, then I can extract the registry key first and
        change its payload, adding the necessary information in the info field.
        In addition, we have to delete the fragmented records, using their key.

        If it didn't go well, then we have to look at the reason. For the time
        being, all records are kept. The last records and the first ones can
        come from an earlier (missing) or later file.
        """
        missing = fragments_verified_result['missing']
        if len(missing) > 0:
            logger.debug(f"Incomplete fragment {row['key']}")
            continue

        # This reassembly is fine
        logger.debug(f"Completed fragment {row['key']}")
        key_record_0 = row['key']
        df_frag.loc[df_frag['key'] == key_record_0]

        # Update payload
        df_frag.loc[df_frag['key'] == key_record_0, 'payload_hex'] = fragments_verified_result['payload_hex']

        # Create the IBR flow entry using create_ibr_flow

        # Remove the fragments from the dataframe that are already reassembled
        df_frag, ts_min_removed, ts_max_removed, removed_keys = remove_fragments_complete(df_frag_search, df_frag)
        logger.debug(f"Removed fragments: {len(removed_keys)}, ts_min: {ts_min_removed}, ts_max: {ts_max_removed}")

        # Create the new key for the reassembled packet
        new_key = f"{key_record_0}_reassembled"

        # Get the timestamp of the reassembled packet
        ts_reassembled = df_frag.loc[df_frag['key'] == key_record_0, 'timestamp'].values[0]
        # Compare ts_reassembled with ts_min_removed and ts_max_removed to get the start and end timestamps
        ts_min_removed = min(ts_min_removed, ts_reassembled)
        ts_max_removed = max(ts_max_removed, ts_reassembled)
        # Add the key to removed keys and sort them
        removed_keys.append(key_record_0)

        # With all information, then create the ibr_flow entry
        previous_ibr_info = df_frag.loc[df_frag['key'] == key_record_0, 'IBR_info'].values[0]
        updated_ibr_info, ibr_flow = create_ibr_flow(
            ibr_flow_id=new_key,
            ts_start=ts_min_removed,
            ts_end=ts_max_removed,
            traffic_list=removed_keys,
            action='reassembly',
            info={
                'fragments_count': fragments_verified_result.get('fragment_count'),
                'fragmented_ip_len': fragments_verified_result.get('fragmented_ip_len')
            },
            previous_ibr_info=previous_ibr_info
        )

        df_frag.loc[df_frag['key'] == key_record_0, 'IBR_info'] = df_frag.loc[df_frag['key'] == key_record_0, 'IBR_info'].apply(
            lambda x: {**updated_ibr_info, 'ibr_flow': ibr_flow}
        )

        df_tmp = df_frag.loc[df_frag['key'] == key_record_0].copy()
        # Update the key field
        df_tmp.loc[:, 'key'] = new_key

        # Remove the IP fragmentation values from df_tmp
        # Really, we should remove all non common fields and create lists in IBR_info
        # with the values of the different individual packets. TODO ;-)
        cols_remove_reassembly_str = [
            'ip_flag_MF', 'ip_orig_flags',
            'ip_flag_DF', 'ip_flag_Error'
        ]
        cols_remove_reassembly_int = [
            'ip_frag', 'ip_len'
        ]

        for col in cols_remove_reassembly_str:
            if col in df_tmp.columns:
                df_tmp.loc[:, col] = ''

        for col in cols_remove_reassembly_int:
            if col in df_tmp.columns:
                df_tmp.loc[:, col] = 0

        if df_reassembled.empty:
            df_reassembled = df_tmp.copy()
        else:
            df_reassembled = pd.concat([df_reassembled, df_tmp], ignore_index=True)

        # Remove the log from df_frag
        df_frag.drop(df_frag.loc[df_frag['key'] == key_record_0].index, inplace=True)

    return df_frag, df_reassembled


def add_nofragmented_info(df):
    """
    Add the information of the non-fragmented packets
    :param df: DataFrame with the non-fragmented packets
    :return: DataFrame with the info field updated
    """
    dict_info = {'fragmented': 'No'}

    # Check if the DataFrame is empty
    if df.empty:
        return df

    # Update the IBR_info field with the previous info and the dict_info
    df['IBR_info'] = df.apply(lambda x: {**x.get('IBR_info', {}), **dict_info}, axis=1)

    return df


def add_fragments_timeout_info(df, time_window):
    """
    Add the information of the fragments that have timed out
    :param df: DataFrame with the fragments
    :param time_window: Time window for the fragments
    :return: DataFrame with the info field updated
    """
    if df.empty:
        return df

    dict_info = {
        'fragmented': 'Yes',
        'fragmens_lost': 'Yes',
        'fragments_timeout': 'Yes',
        'fragmented_time_window': time_window}

    # Update the IBR_info field with the previous info and the dict_info
    df['IBR_info'] = df['IBR_info'].apply(lambda x: {**x, **dict_info})
    # df['IBR_info'] = df.apply(lambda x: {**x.get('IBR_info', {}), **dict_info}, axis=1)

    return df


def get_final_packets(df_reassembled):
    """
    This function gets the total number of packets processed
    :param df_reassembled: DataFrame with the reassembled packets
    :return: Total number of packets processed
    """
    # For the reassemblies dataframe, I have to do a fragment check
    # counting the total number of fragments of all records.
    cnt_total = 0
    for _, row in df_reassembled.iterrows():
        if 'fragmented_count' not in row['IBR_info']:
            continue

        # Keep the info field and then the fragmented_count field.
        cnt_total += row['IBR_info']['fragmented_count']

    logger.info(f"Total of reassembled fragments: {cnt_total}")
    return cnt_total


def filter_ip_fields(df):
    """
    This function filters the IP fields in the dataframe
    :param df: DataFrame with the packets
    :return: DataFrame with the IP fields filtered
    """
    # Fields which are not important now are extracted and
    # are estimated to be stored in the dictionary.
    df = df.drop(coldef.cols_remove_reassembly_success, axis=1)
    df = df.copy()
    return df


def export_to_csv(df, key, op_type, file, output_folder, no_gzip):
    """
    This function exports the reassembled packets to a CSV file
    :param df: DataFrame with the reassembled packets
    :param key: Key of the protocol
    :param op_type: Type of export (e.g., 'reassembled', 'resto')
    :param file: File to export the packets
    :param output_folder: Folder to export the CSV file
    :param no_gzip: Whether to skip gzip compression
    """
    # Set the new file name
    new_sufix = f'_{op_type}_{key}.csv'
    file_csv = os.path.join(output_folder, os.path.basename(file).replace('.csv', new_sufix))

    if df.empty:
        # Do not export empty dataframes to avoid issues in the next steps
        # df.to_csv(file_csv, index=False, sep=";")
        return

    # Sort the dataframe by key, a timestamp and the position in the file
    df = df.sort_values(by=['key']).reset_index(drop=True)

    # Convert the timestamp to epoch to export
    df['timestamp'] = df['timestamp'].apply(convert_to_epoch)

    # Fields that are not important now are extracted and
    # if estimated are stored in the dictionary.
    df = filter_ip_fields(df)

    # Depending on the protocol, I have to select the columns
    if key == 1:  # ICMP
        cols_tmp = coldef.columns_out_icmp
    elif key == 6:  # TCP
        cols_tmp = coldef.columns_out_tcp
    elif key == 17:  # UDP
        cols_tmp = coldef.columns_out_udp
    else:
        cols_tmp = coldef.columns_out_otros

    # Remove the columns removed in the reassembly
    cols_tmp = [col for col in cols_tmp if col not in coldef.cols_remove_reassembly_success]
    df = df[cols_tmp]

    # Ensure IBR_info is a dict and serialize to JSON
    df['IBR_info'] = df['IBR_info'].apply(lambda x: x if isinstance(x, dict) else ({} if pd.isna(x) else {}))
    df['IBR_info'] = df['IBR_info'].apply(lambda x: json.dumps(_to_jsonable(x)))

    df.to_csv(file_csv, index=False, sep=";")
    if not no_gzip:
        # Compress the CSV file
        with open(file_csv, 'rb') as f_in:
            with gzip.open(f"{file_csv}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        # Remove the uncompressed CSV file
        os.remove(file_csv)
        file_csv = f"{file_csv}.gz"

    logger.info(f"Reassembled packets, with protocol key {key}, exported to {file_csv}")
    del df


def export_to_ndjson(df, key, op_type, file, output_folder, no_gzip):
    """
    This function exports the reassembled packets to an NDJSON file (newline-delimited JSON)
    :param df: DataFrame with the reassembled packets
    :param key: Key of the protocol
    :param op_type: Type of export (e.g., 'reassembled', 'resto')
    :param file: File to export the packets
    :param output_folder: Folder to export the NDJSON file
    :param no_gzip: Whether to skip gzip compression
    """
    # Set the new file name
    new_sufix = f'_{op_type}_{key}.ndjson'
    file_ndjson = os.path.join(output_folder, os.path.basename(file).replace('.csv', new_sufix))

    if df.empty:
        # Do not export empty dataframes to avoid issues in the next steps
        return

    # Sort the dataframe by key, a timestamp and the position in the file
    df = df.sort_values(by=['key']).reset_index(drop=True)

    # Convert the timestamp to epoch to export
    df['timestamp'] = df['timestamp'].apply(convert_to_epoch)

    # Fields that are not important now are extracted and
    # if estimated are stored in the dictionary.
    df = filter_ip_fields(df)

    # Depending on the protocol, I have to select the columns
    if key == 1:  # ICMP
        cols_tmp = coldef.columns_out_icmp
    elif key == 6:  # TCP
        cols_tmp = coldef.columns_out_tcp
    elif key == 17:  # UDP
        cols_tmp = coldef.columns_out_udp
    else:
        cols_tmp = coldef.columns_out_otros

    # Remove the columns removed in the reassembly
    cols_tmp = [col for col in cols_tmp if col not in coldef.cols_remove_reassembly_success]
    df = df[cols_tmp]

    # Ensure IBR_info is a dict (keep as dict, don't serialize to string yet)
    df['IBR_info'] = df['IBR_info'].apply(lambda x: x if isinstance(x, dict) else ({} if pd.isna(x) else {}))

    # Convert to NDJSON format (one JSON object per line)
    with open(file_ndjson, 'w') as f:
        for _, row in df.iterrows():
            row_dict = row.to_dict()
            # Convert the entire row to jsonable format
            row_dict = _to_jsonable(row_dict)
            f.write(json.dumps(row_dict) + '\n')

    if not no_gzip:
        # Compress the NDJSON file
        with open(file_ndjson, 'rb') as f_in:
            with gzip.open(f"{file_ndjson}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        # Remove the uncompressed NDJSON file
        os.remove(file_ndjson)
        file_ndjson = f"{file_ndjson}.gz"

    logger.info(f"Reassembled packets, with protocol key {key}, exported to {file_ndjson}")
    del df


def export_resto_core_to_csv(df, file_csv, no_gzip):
    """
    This function exports the reassembled packets to a CSV file
    :param df: DataFrame with the reassembled packets
    :param file_csv: File to export the packets
    """
    if df.empty:
        # Do not export empty dataframes to avoid issues in the next steps
        # df.to_csv(file_csv, index=False, sep=";")
        return

    # Export the dataframe to a CSV file
    df.to_csv(file_csv, index=False, sep=";")
    if not no_gzip:
        # Compress the CSV file
        with open(file_csv, 'rb') as f_in:
            with gzip.open(f"{file_csv}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        # Remove the uncompressed CSV file
        os.remove(file_csv)
        file_csv = f"{file_csv}.gz"

    logger.info(f"Packets exported to {file_csv}")
    del df


def export_resto_to_csv_concatenated(dict_df, file, no_gzip):
    """
    This function exports all the packets that are not reassembled to a CSV file
    :param dict_df: Dictionary with the dataframes of all the protocols
    :param file: File to export the packets
    """
    df = pd.DataFrame()

    for protocol in dict_df:
        df_protocol = dict_df[protocol]
        # Concatenate all the dataframes of the same protocol
        df = join_all_df_with_all_columns(df, df_protocol)

    # Set the new file name
    new_sufix = '_todo.csv'
    file_csv = file.replace('.csv', new_sufix)

    export_resto_core_to_csv(df, file_csv, no_gzip)
    logger.info(f"All no reassembled packet exported to {file_csv}")


def export_resto_to_csv_by_keys(dict_df, file, no_gzip):
    """
    This function exports the packets that are not reassembled to a CSV file
    :param df: DataFrame with the packets that are not reassembled
    :param key: Key of the protocol
    :param file: File to export the packets
    """
    for key in dict_df:
        logger.info(f"Exporting rest of packets for key {key}, len: {dict_df[key].shape[0]}")

        # Set the new file name
        new_sufix = f'_resto_{key}.csv'
        file_csv = file.replace('.csv', new_sufix)

        export_resto_core_to_csv(dict_df[key], file_csv, no_gzip)
        logger.info(f"No reassembled packets, with key {key}, exported to {file_csv}")


def load_new_file(file, dict_df):
    """
    This function joins the files, concatenating the dataframes
    in dict_df with the dataframes in file_faltan.
    :param file: File to join
    :param dict_df: Dictionary with the dataframes
    :return: Dictionary with the dataframes
    """
    # Start information
    start_time_load = time.time()  # Mark the start of loading

    # Load the file
    dict_df_faltan, _, _= load_pcap_csv_gz(file, logger)

    # For every dataframe in dict_df_faltan, I have to concatenate with dict_df
    for key in dict_df_faltan:
        logger.info(f"New packets loaded for key {key}: {len(dict_df_faltan[key])}")

        if key in dict_df:
            logger.info(f"Previosly loaded packets for key {key}: {len(dict_df[key])}")
            dict_df[key] = pd.concat([dict_df[key], dict_df_faltan[key]])

            # Sort by timestamp
            dict_df[key] = dict_df[key].sort_values(by=['timestamp']).reset_index(drop=True)

            # Reset index
            dict_df[key] = dict_df[key].reset_index(drop=True)
        else:
            dict_df[key] = dict_df_faltan[key]

        logger.info(f"Total packets joined for {key}: {len(dict_df[key])}")

    # Log and stat information
    end_time_load = time.time()  # Mark the end of loading
    load_time = end_time_load - start_time_load
    logger.info(f"Load time: {load_time} seconds.")

    return dict_df


def convert_to_epoch(timestmp):
    """
    This function converts a timestamp to epoch
    :param timestamp: Timestamp to convert
    :return: Timestamp in epoch format
    """
    tmsmp = float(f"{timestmp.timestamp():.9f}")

    return tmsmp


def join_all_df_with_all_columns(df_frag_total, df_frag):
    """
    Using the key, this function includes all the columns in the df_frag
    dataframe and then concatenates with the df_frag_total dataframe.
    :param df_frag_total: DataFrame with all the packets
    :param df_frag: DataFrame with the packets to add
    :return: DataFrame with all the packets
    """
    df = df_frag.copy()

    # Check if the dataframe df is empty and return
    if df.empty:
        return df_frag_total

    # Resto cols includes all columns that are not in the dataframe
    resto_cols = list(coldef.columns_out_otros)

    # Add all columns to the dataframe
    for col in resto_cols:
        if col not in df.columns:
            df[col] = None

    # Sort the columns in the right order, using coldef.col_order_new
    df = df[coldef.col_order]
    df_frag_total = pd.concat([df_frag_total, df])

    return df_frag_total


def add_fragments_to_df_frag_total(df_frag_total, df_frag):
    """
    Using the key, this function includes all the columns in the df_frag
    dataframe and then concatenates with the df_frag_total dataframe.
    :param df_frag_total: DataFrame with all the packets
    :param df_frag: DataFrame with the packets to add
    :return: DataFrame with all the packets
    """
    if df_frag_total.empty:
        return df_frag_total

    df = df_frag.copy()
    df_frag_total = pd.concat([df_frag_total, df])

    return df_frag_total


def process_chunk(df_reassembled, df_frag, df_frag_chunk, time_window_gap):
    """
    This function processes a chunk of packets
    :param df_reassembled: DataFrame with the reassembled packets
    :param df_frag: DataFrame with the fragmented packets
    :param df_frag_chunk: DataFrame with the fragmented packets in a chunk
    :param time_window_gap: Time window for reassembly
    :return: DataFrame with the reassembled packets, DataFrame with the fragmented packets
    """
    # Concat the fragmented packets
    if df_frag_chunk.empty and df_frag.empty:
        return df_reassembled, df_frag

    if not df_frag_chunk.empty and not df_frag.empty:
        df_frag = pd.concat([df_frag, df_frag_chunk])
    else:
        if df_frag.empty:
            df_frag = df_frag_chunk

    if df_frag.empty:
        return df_reassembled, df_frag

    # Process the chunk and save the reassembled packets
    df_frag, df_reassembled = process_fragmented_packets(df_frag, df_reassembled, time_window_gap)

    return df_reassembled, df_frag


def print_key_stats(n_df_key, n_fragmented, n_non_fragmented, df_reassembled, file_name, protocol_key):
    """
    This function prints the statistics of the dataframe
    :param n_df_key: Total number of packets in the dataframe
    :param n_frag: Number of fragmented packets
    :param n_no_frag: Number of non-fragmented packets
    :param df_reassembled: DataFrame with the reassembled packets
    """
    # Total packets processed
    total_packet_processed = get_final_packets(df_reassembled)

    logging.info(f"Reassembly statistics for file: {file_name}, protocol key: {protocol_key}")
    logging.info(f"Packets total: {n_df_key}")
    logging.info(f"Packets with fragmentation: {n_fragmented}")
    logging.info(f"Packets without fragmentation: {n_non_fragmented}")
    logging.info(f"Packets processed: {total_packet_processed}")
    logging.info(f"Packets reassembed: {df_reassembled.shape[0]}")


def protocol_reassembly(df, chunk_size, time_window_gap, file_name, protocol_key):
    """
    This function reassembles the packets of a protocol. It takes a
    dictionary with the dataframes of all the protocols, the key of the
    protocol to reassemble, the chunk size for processing, the final timestamp
    for processing, the time window from the first packet, the time window for
    reassembly and the file name. Then, select the dataframe to process, process
    it in chunks and export the reassembled packets to a CSV file with the name
    of the input file and the protocol key.

    Therefore, all packets that are reassembled are exported to a CSV file. The
    packets that are not reassembled and the timestamp is greater than the final
    timestamp are also exported to the CSV file, including the information about
    the fragments.

    The fragments that are not reassembled are stored in a DataFrame, which is
    returned at the end of the function.

    :param df: Dataframe input for the current key
    :param chunk_size: Chunk size for processing
    :param time_window_gap: Time window for reassembly
    :return: DataFrame with all the fragmented packets
    """
    df_frag_total = pd.DataFrame()
    df_reassembled = pd.DataFrame()  # Dataframe for the reassembled packets
    df_frag = pd.DataFrame()  # Dataframe for the fragmented packets

    # Stats values
    n_df_key = df.shape[0]  # Total number of packets in the dataframe

    # The faster processing is remove the non-fragmented packets first
    # and then process only the fragmented packets.
    df_fragmented_all, df_non_fragmented_all = split_fragmented_datasets(df)
    n_fragmented = df_fragmented_all.shape[0]
    n_non_fragmented = df_non_fragmented_all.shape[0]
    logger.info(f"Total packets: {n_df_key}, fragmented: {n_fragmented}, non-fragmented: {n_non_fragmented}")

    # Add info to non-fragmented packets
    df_non_fragmented_all = add_nofragmented_info(df_non_fragmented_all)

    # The dataframe is processed in blocks (chunks) of chunk_size
    for i in range(0, df_fragmented_all.shape[0], chunk_size):
        logger.debug(f"Processing block {i} - {i + chunk_size}")
        df_key_block = df_fragmented_all[i:i + chunk_size]

        # Get the maximum timestamp in the chunk, used to move the old fragments
        timestamp_max = df_key_block['timestamp'].max()
        logger.debug(f"Timestamp max: {timestamp_max}")

        # Process the chunk
        df_reassembled, df_frag  = process_chunk(df_reassembled, df_frag, df_key_block, time_window_gap)
        logger.debug(f"Chunk: Fragmented packets after processing: {df_frag.shape[0]} and reassembled: {df_reassembled.shape[0]}")
        if df_frag.empty:
            continue

        # Move the packet fragmented with timestamp greater than the maximum timestamp minus the time_window_gap
        df_frag_mover = df_frag[df_frag['timestamp'] < timestamp_max - pd.to_timedelta(time_window_gap, unit='s')]
        df_frag_mover = df_frag_mover.copy()

        # Remove the df_frag_mover from df_frag
        df_frag = df_frag[~df_frag['key'].isin(df_frag_mover['key'])]
        df_frag = df_frag.copy()

        logger.info(f"Chunk: Fragments moved: {df_frag_mover.shape[0]}. Total fragments: {df_frag.shape[0]}")
        df_frag_mover = add_fragments_timeout_info(df_frag_mover, time_window_gap)

        if not df_frag_mover.empty:
            df_reassembled = pd.concat([df_reassembled, df_frag_mover], ignore_index=True)

    # Save the packets that are not reassembled
    df_frag_total = add_fragments_to_df_frag_total(df_frag_total, df_frag)
    logger.info(f"Packets not reassembled: {df_frag_total.shape[0]}")

    # Print statistics
    print_key_stats(n_df_key, n_fragmented, n_non_fragmented, df_reassembled, file_name, protocol_key)

    return df_frag_total, df_reassembled, df_non_fragmented_all


def load_and_reassembly(files, file_faltan, time_window_gap, chunk_size, logger, output_folder, no_gzip):
    """
    This function is the core of the IP fragments reassembly module.
    It loads the files and processes the packets, reassembling the
    fragmented packets and exporting the reassembled packets to a CSV file.
    The packets that are not reassembled are also exported to a CSV file.
    :param files: List of files to process
    :param file_faltan: File with the packets that are not reassembled
    :param time_window_gap: Time window for reassembly
    :param chunk_size: Chunk size for processing
    :param logger: Logger object
    """
    logger.debug("IP Fragments Reassembly Module initialized")

    if not files:
        logger.error("No input files found.")
        return

    # Create an empty dictionary to store the dataframes
    dict_df = {}

    # If file_faltan is set, then I have to load it and concatenate with the main file
    if file_faltan:
        dict_df = load_new_file(file_faltan, dict_df)

    # Save the name of the last file processed
    last_file_name = None

    for file in files:
        last_file_name = file
        logger.info(f"Processing file {file} ...")

        # Log current packets to reassembly
        for key in dict_df:
            logger.info(f"Current packets to reassembly, protocolo {key}: {dict_df[key].shape[0]}")

        # Load new files
        dict_df = load_new_file(file, dict_df)

        # Apply the reassembly for all the protocols
        for key in dict_df:
            df_fragmented, df_reassembled, df_non_fragmented = protocol_reassembly(dict_df[key], chunk_size, time_window_gap, file, key)

            # Export dataframes to CSV
            export_to_csv(df_reassembled, key, "reassembled", file, output_folder, no_gzip)  # Reassembled packets
            export_to_ndjson(df_reassembled, key, "reassembled", file, output_folder, no_gzip)  # Reassembled packets in NDJSON
            export_to_csv(df_non_fragmented, key, "non_fragmented", file, output_folder, no_gzip)  # Non-fragmented packets

            # Move the rest of the packets to the df in the dict_df
            dict_df[key] = df_fragmented
            logger.info(f"Packets not reassembled for protocol {key}: {dict_df[key].shape[0]}")

    # Export the rest of the packets to a CSV files, one by one and concatenated
    export_resto_files(dict_df, last_file_name, output_folder, no_gzip)


def export_resto_files(dict_df, file, output_folder, no_gzip):
    # Because the timestamp is converted to float to export,
    # and we cannot call twice the convert to epoch function,
    # is better to convert it first and then export in both file types
    for key in dict_df:
        df = dict_df[key]
        if df.empty:
            continue

        # Convert timestamp to epoch format
        df['timestamp'] = df['timestamp'].apply(convert_to_epoch)
        df.sort_values(by=['timestamp'], inplace=True)

        # Ensure IBR_info is a dict and serialize to JSON
        df['IBR_info'] = df['IBR_info'].apply(lambda x: x if isinstance(x, dict) else ({} if pd.isna(x) else {}))
        df['IBR_info'] = df['IBR_info'].apply(lambda x: json.dumps(_to_jsonable(x)))
        dict_df[key] = df

    lfile = os.path.join(output_folder, os.path.basename(file))
    export_resto_to_csv_by_keys(dict_df, lfile, no_gzip)
    export_resto_to_csv_concatenated(dict_df, lfile, no_gzip)


# # MAIN
if __name__ == '__main__':
    # Optional flags
    flag_include_rest_output = False
    flag_output_rest_asfile = False
    default_loglevel = 'CRITICAL'
    default_chunk_size = 50000000
    default_time_window_gap = 60
    file_faltan = None

    parser = argparse.ArgumentParser(description="Reassembly IP fragments from CSV files")
    parser.add_argument(
        "paths",
        nargs="+",
        help=(
            "One or more input folders/files followed by the output folder. "
            "Inputs can be folders or CSV files (.csv, .csv.gz, .csv.xz). "
            "All but the last positional are treated as inputs; the last is the output folder."
        ),
    )
    parser.add_argument('-r', action='store_true', help='First file is rest of previous file')
    parser.add_argument('-i', action='store_true', help='Include rest in the reassembly output')
    parser.add_argument('-o', action='store_true', help='Output rest of packets as file')
    parser.add_argument('-s', action='store_true', help='Do not sort input files by name')
    parser.add_argument('-g', '--no-gzip', action='store_true', help='Do not use gzip compression when exporting CSV files')
    parser.add_argument('--time_window_gap', type=int, default=default_time_window_gap, help=f'Window time for reassembly. Default: {default_time_window_gap} seconds')
    parser.add_argument('--chunk_size', type=int, default=default_chunk_size, help=f'Chunk size for processing. Default: {default_chunk_size} packets')
    parser.add_argument('--loglevel', type=str, default=default_loglevel, help='Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    args = parser.parse_args()

    # Validate and split positional arguments: inputs and output folder
    if len(args.paths) < 2:
        parser.error("Expected at least one input and an output folder")
    output_folder = args.paths[-1]
    input_paths = args.paths[:-1]

    # Convert the log level to upper case, as it is named in the logging module
    loglevel = getattr(logging, args.loglevel.upper(), logging.DEBUG)

    # Logger configuration
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=loglevel)

    # Get the list of files from the input folders or files
    files = []
    for in_path in input_paths:
        if os.path.isdir(in_path):
            for ext in ('*.csv', '*.csv.gz', '*.csv.xz'):
                files.extend(glob.glob(os.path.join(in_path, ext)))
        else:
            if ',' in in_path:
                files.extend([f.strip() for f in in_path.split(',') if f.strip()])
            else:
                files.append(in_path)

    files = [f.strip() for f in files]
    if not files:
        logger.error("No input files found.")
        exit(1)

    # Log and stat information
    logger.info(f"Input files: {files}")
    logger.info(f"Output folder: {output_folder}")

    # Create output folder if it does not exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    else:
        logger.error(f"Output folder {output_folder} already exists.")
        exit(1)

    # Optional flags
    if args.r:
        # If "r" flag is set, then the first file is the rest of the previous file
        file_faltan = files[0]
        files = files[1:]

    if args.i:
        flag_include_rest_output = True

    if args.o:
        flag_output_rest_asfile = True

    if not args.s:
        # Sort the files by name
        files.sort()

    # Process the files
    logger.info(f"Processing files: {files}, file_faltan: {file_faltan}, time_window_gap: {args.time_window_gap}, chunk_size: {args.chunk_size}")
    load_and_reassembly(files, file_faltan, args.time_window_gap, args.chunk_size, logger, output_folder, args.no_gzip)
