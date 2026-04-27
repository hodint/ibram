import json
import pandas as pd
import coldefinitions as coldef


def limpia_datos_protocolo(df, ip_proto):
    # Remove columns that have no data because they are not part of this protocol
    if ip_proto == 1:
        df = df[coldef.columns_out_icmp]
    elif ip_proto == 17:
        df = df[coldef.columns_out_udp]
    elif ip_proto == 6:
        df = df[coldef.columns_out_tcp]
    else:
        # Drop columns from other protocols
        # NOTE: ip_payload fields cannot be removed because in fragmented packets,
        # fragments after the first one keep their data in this field.
        df = df[coldef.columns_out_otros]

    df = df.copy()
    return df


def obtener_fecha_inferior(df):
    """
    Return the earliest timestamp in a dataframe.
    """
    return df['timestamp'].min()


def obtener_fecha_superior(df):
    """
    Return the latest timestamp in a dataframe.
    """
    return df['timestamp'].max()


def convierte_columna_timestamp(df):
    """
    Convert the dataframe "timestamp" column to datetime type.
    """
    df['timestamp'] = df['timestamp'].astype(float)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    return df


def ajusta_tipos_datos_protocolo(df, ip_proto):
    # Apply shared IP types for all protocols
    df = df.astype(coldef.ip_types)

    # Then apply protocol-specific types
    if ip_proto == 1:  # ICMP
        df = df.astype(coldef.icmp_types)
    elif ip_proto == 6:  # TCP
        df = df.astype(coldef.tcp_types)
    elif ip_proto == 17:  # UDP
        df = df.astype(coldef.udp_types)
    return df


def divide_dataframe_en_protocolos(df, logger):
    """
    Split dataframe df into a dictionary of dataframes, one per protocol.
    If a protocol already exists in the dictionary, append new data at the end.
    """
    dict_dfs = {}

    for ip_proto in df['ip_proto'].unique():
        # Get current protocol data into a dataframe
        df_tmp = df[df['ip_proto'] == ip_proto]
        df_tmp = df_tmp.copy()

        # Remove columns not needed for this protocol
        df_tmp = limpia_datos_protocolo(df_tmp, ip_proto)

        # Adjust data types for protocol columns
        df_tmp = ajusta_tipos_datos_protocolo(df_tmp, ip_proto)

        # Check whether the dataframe already exists
        if ip_proto not in dict_dfs:
            logger.info(f"Cargando el protocolo {ip_proto}. Creo el dataframe con {len(df_tmp)} registros")
            dict_dfs[ip_proto] = df_tmp
        else:
            logger.info(f"Cargando el protocolo {ip_proto}. Actualizo el dataframe de {len(dict_dfs[ip_proto])} registros con {len(df_tmp)} registros")
            # Get existing dataframe for this protocol from the dictionary
            df_tmp_orig = dict_dfs[ip_proto]

            # Append new rows at the end of the dataframe
            # df_tmp_orig = df_tmp_orig.append(df_tmp, ignore_index=True)
            df_tmp_orig = pd.concat([df_tmp_orig, df_tmp], ignore_index=True)

            # Update the dataframe in the dictionary
            dict_dfs[ip_proto] = df_tmp_orig

    del(df)  # Delete original dataframe to free memory
    return dict_dfs


def load_pcap_csv_gz(file_name, logger):
    """
    Load a CSV (possibly gzipped) file containing pcap data into a dictionary of dataframes,
    divided by transport protocol.

    :param file_name: The path to the CSV file.
    :param logger: Logger object for logging information.
    :return: A tuple containing a dictionary of dataframes (keyed by protocol) and
             the base and top dates of the loaded data.
    """
    logger.info(f"Loading file {file_name}")

    # if file is compressed gzip
    if file_name.endswith('.gz'):
        df = pd.read_csv(file_name, compression='gzip', sep=';',
                        names=list(coldef.col_type_csv_import.keys()),
                        dtype=coldef.col_type_csv_import,
                        keep_default_na=False, encoding='latin1')
    else:
        df = pd.read_csv(file_name, sep=';',
                        names=list(coldef.col_type_csv_import.keys()),
                        dtype=coldef.col_type_csv_import,
                        keep_default_na=False, encoding='latin1')

    # IBR_info is a dictionary column, but it was loaded as string. Convert it to dict
    df['IBR_info'] = df['IBR_info'].apply(json.loads)

    # Add timestamp as a datetime column
    df = convierte_columna_timestamp(df)

    # Get the base date (oldest date in the loaded data)
    fecha_base = obtener_fecha_inferior(df)
    fecha_top = obtener_fecha_superior(df)
    logger.info(f"Data loaded from file {file_name}, with date range: {fecha_base} to {fecha_top}")

    # Once loaded, split dataframes by transport protocol
    dict_df_pool = divide_dataframe_en_protocolos(df, logger)

    return dict_df_pool, fecha_base, fecha_top
