"""
This script reads .ndjson (ibrflow) and .csv (enriched tshark output) files,
both gzip compressed and uncompressed, and loads them into a dataframe.

It uses two different functions for loading, one for ndjson and one for csv.
It checks whether the files are compressed or not.

Once loaded, it executes several functions on the dataframe,
each of which adds an additional column,
incorporating information about whether the tool used for that
flow is one or the other (Mirai, ZMap, MasScan, etc.).
"""
import time
import pandas as pd
import logging
from pca_file_load import load_df_from_pcap_csv_gz, load_df_from_pcap_ndjson_gz


def load_ndjson(file_path: str, logger: logging.Logger) -> pd.DataFrame:
    """
    Load an NDJSON file (newline-delimited JSON, possibly gzipped).
    :param file_path: Path to the NDJSON file
    :param logger: Logger object for logging information
    :return: DataFrame with the loaded data
    """
    # Start information
    start_time_load = time.time()  # Marca el inicio de la carga

    # Load the file
    df = load_df_from_pcap_ndjson_gz(file_path, logger)
    logger.info(f"File {file_path} loaded with {len(df)} packets.")

    # Sort by timestamp
    df = df.sort_values(by=['timestamp']).reset_index(drop=True)

    # Reset index
    df = df.reset_index(drop=True)

    # Log and stat information
    end_time_load = time.time()  # Marca el final de la carga
    load_time = end_time_load - start_time_load
    logger.info(f"Load time: {load_time} seconds.")

    return df


def load_csv(file: str, logger: logging.Logger) -> pd.DataFrame:
    """
    This function joins the files, concatenating the dataframes
    in dict_df with the dataframes in file_faltan.
    :param file: File to join
    :param dict_df: Dictionary with the dataframes
    :return: Dictionary with the dataframes
    """
    # Start information
    start_time_load = time.time()  # Marca el inicio de la carga

    # Load the file
    df = load_df_from_pcap_csv_gz(file, logger)

    logger.info(f"File {file} loaded with {len(df)} packets.")

    # Sort by timestamp
    df = df.sort_values(by=['timestamp']).reset_index(drop=True)

    # Reset index
    df = df.reset_index(drop=True)

    # Log and stat information
    end_time_load = time.time()  # Marca el final de la carga
    load_time = end_time_load - start_time_load
    logger.info(f"Load time: {load_time} seconds.")

    return df


def load_file(file_path: str, logger: logging.Logger) -> pd.DataFrame:
    """Load a file into a pandas DataFrame based on its extension."""
    if file_path.endswith('.ndjson') or file_path.endswith('.ndjson.gz'):
        return load_ndjson(file_path, logger)
    elif file_path.endswith('.csv') or file_path.endswith('.csv.gz'):
        return load_csv(file_path, logger)
    else:
        raise ValueError("Unsupported file format. Only .ndjson and .csv are supported.")


if __name__ == "__main__":
    # Example usage
    ndjson_file = "07_testing/darknet_20251021_mod_17_reassembled.ndjson"
    csv_file = "07_testing/darknet_20251021_mod_6_non_fragmented.csv.gz"

    # Logger configuration
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)

    df_ndjson = load_file(ndjson_file, logger)
    print("NDJSON DataFrame:")
    print(df_ndjson.head())

    df_csv = load_file(csv_file, logger)
    print("CSV DataFrame:")
    print(df_csv.head())
