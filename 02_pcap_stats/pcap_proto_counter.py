import os
import glob
import gzip
import lzma
import json
import tempfile
import argparse
from scapy.all import PcapReader, IP, IPv6
from collections import Counter


def resolve_input_files(inputs):
    """
    Given directory names, wildcard patterns, or explicit file paths,
    resolve a unique sorted list of .pcap, .pcap.gz and .pcap.xz files.
    """
    if isinstance(inputs, str):
        inputs = [inputs]

    files = []
    for item in inputs:
        if os.path.isdir(item):
            files.extend(
                os.path.join(item, f)
                for f in os.listdir(item)
                if f.endswith((".pcap", ".pcap.gz", ".pcap.xz"))
            )
        else:
            files.extend(glob.glob(item))

    # Only keep valid extensions and deduplicate
    seen = set()
    unique_files = []
    for f in sorted(files):
        if f.endswith((".pcap", ".pcap.gz", ".pcap.xz")) and f not in seen:
            unique_files.append(f)
            seen.add(f)
    return unique_files


def decompress_if_needed(path):
    """
    Return (usable_path, temp_path)
    usable_path = path to use
    temp_path = temporary file to delete later (or None if no temp was created)
    """
    if path.endswith(".pcap"):
        return path, None

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp.name
    tmp.close()

    if path.endswith(".pcap.gz"):
        opener = gzip.open
    elif path.endswith(".pcap.xz"):
        opener = lzma.open
    else:
        raise ValueError(f"Unsupported format: {path}")

    with opener(path, "rb") as comp, open(tmp_path, "wb") as out:
        out.write(comp.read())

    return tmp_path, tmp_path


def load_existing_processed(output_file):
    """
    Load previously processed file entries to avoid reprocessing.
    Returns a set of processed filenames.
    """
    processed = set()
    if not os.path.isfile(output_file):
        return processed

    with open(output_file, "r") as f:
        for line in f:
            try:
                entry = json.loads(line)
                processed.add(entry.get("file"))
            except:
                pass
    return processed


def process_file(path):
    """
    Process a single pcap file, returning a dict with:
    {"file": <filename>, protocol_number: count, ..., "total": N, "error": 0|1}
    If processing fails, return error=1 and total=0.
    """
    result = {"file": os.path.basename(path)}

    try:
        usable, temp = decompress_if_needed(path)
        counts = Counter()

        with PcapReader(usable) as reader:
            for pkt in reader:
                if IP in pkt:
                    proto = pkt[IP].proto
                elif IPv6 in pkt:
                    proto = pkt[IPv6].nh
                else:
                    proto = "other"
                counts[str(proto)] += 1

        total = sum(counts.values())
        result.update(counts)
        result["total"] = total
        result["error"] = 0

    except Exception as e:
        result["total"] = 0
        result["error"] = 1

    finally:
        if "temp" in locals() and temp:
            try:
                os.remove(temp)
            except:
                pass

    return result


def main():
    parser = argparse.ArgumentParser(description="Process PCAP files and record per-file protocol statistics.")
    parser.add_argument("inputs", nargs="+", help="Input directories, files, or wildcard patterns.")
    parser.add_argument("-w", "--write-output", required=True, help="Output JSON-lines file.")
    args = parser.parse_args()

    output_file = args.write_output
    processed = load_existing_processed(output_file)

    pcap_files = resolve_input_files(args.inputs)

    with open(output_file, "a") as out:
        for path in pcap_files:
            fname = os.path.basename(path)
            if fname in processed:
                print(f"⚠️ Skipping already processed: {fname}")
                continue

            print(f"   Processing: {path}")
            record = process_file(path)
            print(f"✅ File processed: {record}")
            out.write(json.dumps(record) + "\n")
            out.flush()


if __name__ == "__main__":
    main()
