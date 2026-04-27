import argparse
import subprocess
import gzip
import shutil
import os
import logging
import sys

# Define the path to the tshark executable
def find_tshark_path(possible_paths=None):
    """
    Searches for the `tshark` executable in a list of specified locations.

    Args:
        possible_paths (list): A list of possible paths to search for `tshark`.
                               If not provided, default paths will be used.

    Returns:
        str: The first valid path to `tshark`, or None if not found.
    """
    # Default paths if none are provided
    if possible_paths is None:
        possible_paths = [
            r"/c/Program Files/Wireshark/tshark.exe",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            r"C:\Program Files\Wireshark\tshark.exe"]

    # Find the first valid path
    for path in possible_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)


def file_convert(pcap_file, output_folder, tshark_cmd, fields, no_gzip=False, separator=";"):
    """
    Convert .pcap.gz or .pcap.xz file to .csv.gz using tshark.
    :param pcap_file: Input PCAP file (.pcap, .pcap.gz, .pcap.xz)
    :param output_folder: Destination folder for the output CSV file
    :param tshark_cmd: Path to the tshark executable
    :param fields: tshark fields to include in the CSV file
    :param no_gzip: If True, do not compress output chunks
    :param separator: Separator for the CSV file
    """
    logging.info(f"Decompressing {pcap_file}...")
    if pcap_file.endswith(".pcap.xz"):
        # Create temporary files
        temp_pcap = pcap_file.replace(".pcap.xz", "_tmp.pcap")
        csv_file = pcap_file.replace(".pcap.xz", ".csv")
        output_file = pcap_file.replace(".pcap.xz", ".csv.gz")
        with gzip.open(pcap_file, 'rb') as f_in, open(temp_pcap, 'wb') as f_out:
            f_out.write(f_in.read())
    elif pcap_file.endswith(".pcap.gz"):
        temp_pcap = pcap_file.replace(".pcap.gz", "_tmp.pcap")
        csv_file = pcap_file.replace(".pcap.gz", ".csv")
        output_file = pcap_file.replace(".pcap.gz", ".csv.gz")
        with gzip.open(pcap_file, 'rb') as f_in, open(temp_pcap, 'wb') as f_out:
            f_out.write(f_in.read())
    elif pcap_file.endswith(".pcap"):
        temp_pcap = pcap_file.replace(".pcap", "_tmp.pcap")
        csv_file = pcap_file.replace(".pcap", ".csv")
        output_file = pcap_file.replace(".pcap", ".csv.gz")
        shutil.copyfile(pcap_file, temp_pcap)
    else:
        logging.error(f"Unsupported file format: {pcap_file}")
        exit(1)

    # Output file path
    output_file = os.path.join(output_folder, os.path.basename(output_file))

    tshark_cmd = [
        tshark_cmd,
        "-r", temp_pcap,
        "-T", "fields",
        "-o", "ip.defragment:FALSE",
        "-E", "separator=" + separator,
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    # Add fields to the tshark command
    for field in fields:
        tshark_cmd.extend(["-e", field])

    with open(csv_file, "w") as csv_out:
        logging.info(f"Running tshark command: {' '.join(tshark_cmd)}")
        subprocess.run(tshark_cmd, stdout=csv_out, check=True)

    try:
        with open(csv_file, "w") as csv_out:
            subprocess.run(tshark_cmd, stdout=csv_out, check=True)
        logging.info(f"Successfully converted {pcap_file} to {csv_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error converting {pcap_file} to CSV: {e}")
    except Exception as e:
        logging.error(f"Unexpected error for file {pcap_file}: {e}")

    # Compress the CSV file with gzip
    if no_gzip:
        logging.info(f"Skipping compression for {csv_file} as --no-gzip is set.")
        dest_file = output_file.replace(".gz", "")
        shutil.move(csv_file, dest_file)
        logging.info(f"Output file: {dest_file}")
    else:
        logging.info(f"Compressing {csv_file} to {output_file}...")
        with open(csv_file, "rb") as f_in, gzip.open(output_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        # Remove temporary CSV file
        os.remove(csv_file)

    # Remove temporary PCAP file
    os.remove(temp_pcap)


def convert_pcap_gz_to_csv_gz(input_pcap: str, output_folder: str,
                              fields: list, no_gzip: bool = False,
                              separator: str = ';'):
    """
    Convert .pcap compressed file with .gz to .csv.gz using tshark.

    :param input_pcap: Input PCAP file or folder (.pcap, .pcap.gz, .pcap.xz)
    :param output_folder: Destination folder for chunked PCAPs
    :param fields: tshark fields to include in the CSV file
    :param no_gzip: If True, do not compress output chunks
    :param separator: Separator for the CSV file
    """
    # Define the path to the tshark executable
    tshark_cmd = find_tshark_path()
    if tshark_cmd:
        logging.info(f"Tshark found at: {tshark_cmd}")
    else:
        logging.info("Tshark was not found in the specified locations.")
        exit(1)

    if os.path.isdir(input_pcap):
        pcap_files = [os.path.join(input_pcap, f) for f in os.listdir(input_pcap)
                      if f.endswith('.pcap') or f.endswith('.pcap.gz') or f.endswith('.pcap.xz')]
        for pcap in pcap_files:
            file_convert(pcap, output_folder, tshark_cmd, fields, no_gzip, separator)
        return
    elif os.path.isfile(input_pcap):
        file_convert(input_pcap, output_folder, tshark_cmd, fields, no_gzip, separator)
    else:
        logging.error(f"Input path {input_pcap} is neither a file nor a directory.")
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert .pcap.gz file to .csv.gz using tshark.")
    parser.add_argument("-g", "--no-gzip", action="store_true", help="Do not compress output chunks (default: compress)")
    parser.add_argument("input_pcap", help="Folder or PCAP file (.pcap, .pcap.gz, .pcap.xz)")
    parser.add_argument("output_folder", help="Destination folder for chunked PCAPs")

    args = parser.parse_args()

    # Fields to include in the CSV file
    fields = [
        "frame.time_epoch", "ip.version", "ip.hdr_len", "ip.dsfield",
        "ip.tos", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len", "ip.id",
        "ip.flags", "ip.flags.mf", "ip.flags.df", "ip.flags.rb",
        "ip.frag_offset", "ip.ttl", "ip.proto", "ip.checksum", "ip.src",
        "ip.dst", "icmp.type", "icmp.code", "icmp.ident", "icmp.seq",
        "icmp.checksum", "udp.srcport", "udp.dstport", "udp.length",
        "udp.checksum", "tcp.srcport", "tcp.dstport", "tcp.seq_raw",
        "tcp.ack_raw", "tcp.flags", "tcp.flags.cwr", "tcp.flags.ack",
        "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.urg",
        "tcp.flags.fin", "tcp.flags.ece", "tcp.flags.str",
        "tcp.window_size_value", "tcp.checksum", "tcp.urgent_pointer",
        "tcp.options", "udp.payload", "tcp.payload", "data", "data.text"]

    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)
    else:
        print(f"ERROR: Output folder {args.output_folder} already exists. Please specify a non-existing folder.")
        sys.exit(1)

    convert_pcap_gz_to_csv_gz(args.input_pcap, args.output_folder, fields, args.no_gzip, separator=';')
