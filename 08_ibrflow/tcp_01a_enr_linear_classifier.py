#!/usr/bin/env python3
"""
TCP Traffic Classifier with Sliding Windows

This script processes daily CSV files using sliding windows to classify traffic
using detection functions (Mirai, ZMap, Masscan, Hajime, Unicorn).

The sliding window approach ensures that records at day boundaries are properly
evaluated with context from adjacent days.

Window strategy:
- Window size: 24 hours
- Window slide: 12 hours
- This means each 12-hour segment is evaluated twice with different contexts

Usage:
    python tcp_sliding_window_classifier.py <source_dir> <dest_dir> [-g]

Arguments:
    source_dir: Directory containing input CSV files
    dest_dir: Directory where output files will be saved
    -g: Do not compress output files (default: compress with gzip)
"""

import argparse
import logging
import sys
from pathlib import Path
import pandas as pd
import json
from tcp_enrichment_tools import load_file
from algo_tcp import (
    add_hajime_column,
    add_masscan_column,
    add_mirai_column,
    add_unicorn_column,
    add_zmap_column,
)

# Classification columns added by the detection functions
CLASSIFICATION_COLUMNS = ['mirai', 'zmap', 'masscan', 'hajime', 'hajime_possible', 'unicorn']


def setup_logger() -> logging.Logger:
    """Configure and return the logger."""
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logger


def get_sorted_files(source_dir: str, logger: logging.Logger):
    """Get list of CSV files sorted by name (assumes chronological naming)."""
    source_path = Path(source_dir)

    if not source_path.exists():
        logger.error(f"Source directory does not exist: {source_dir}")
        sys.exit(1)

    # Get all CSV files (including .csv.gz)
    files = list(source_path.glob("*.csv")) + list(source_path.glob("*.csv.gz"))

    # Take only files with the _6.csv string in the name
    files = [f for f in files if '_6.csv' in f.name]

    # Sort files by name
    files = sorted(files)

    if not files:
        logger.error(f"No CSV files found in: {source_dir}")
        sys.exit(1)

    logger.info(f"Found {len(files)} files to process")
    return files


def apply_classification_functions(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Apply all classification functions to the dataframe."""
    logger.debug("Applying Mirai classification...")
    df = add_mirai_column(df)

    logger.debug("Applying ZMap classification...")
    df = add_zmap_column(df)

    logger.debug("Applying Masscan classification...")
    df = add_masscan_column(df)

    logger.debug("Applying Hajime classification...")
    df = add_hajime_column(df)

    logger.debug("Applying Unicorn classification...")
    df = add_unicorn_column(df)

    return df


# Ensure IBR_info is a dict for each row
def update_ibr_info(row, classification_columns=CLASSIFICATION_COLUMNS):
    ibr = row.get('IBR_info', '{}')
    try:
        ibr_dict = json.loads(ibr) if isinstance(ibr, str) else (ibr if isinstance(ibr, dict) else {})
    except Exception:
        ibr_dict = {}

    for col in classification_columns:
        if col in row:
            ibr_dict[col] = row[col]
    return json.dumps(ibr_dict)


def move_classification_columns_to_ibr_info(df, classification_columns=CLASSIFICATION_COLUMNS):
    """
    Move classification columns into the IBR_info JSON field for each row.
    """
    df = df.copy()
    for col in classification_columns:
        if col not in df.columns:
            continue

    df['IBR_info'] = df.apply(update_ibr_info, axis=1, classification_columns=classification_columns)
    df = df.drop(columns=classification_columns)
    return df


def save_dataframe(
    df: pd.DataFrame,
    output_path: Path,
    compress: bool,
    logger: logging.Logger
) -> None:
    """Save dataframe to CSV file, optionally compressed."""
    if compress:
        output_file = output_path.with_suffix('.csv.gz')
        df.to_csv(output_file, index=False, compression='gzip')
    else:
        output_file = output_path.with_suffix('.csv')
        df.to_csv(output_file, index=False)

    logger.info(f"Saved: {output_file} ({len(df)} records)")


def process_files_with_sliding_window(
    source_dir: str,
    dest_dir: str,
    compress: bool,
    logger: logging.Logger
) -> None:
    """
    Process files in source_dir using sliding windows and save results to dest_dir.
    """
    # Get sorted list of files
    files = get_sorted_files(source_dir, logger)

    # Create destination directory if it doesn't exist
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)


    for i, current_file in enumerate(files):
        logger.info(f"Processing file {i+1}/{len(files)}: {current_file.name}")

        # Load current day
        current_df = load_file(str(current_file), logger)

        if current_df is None or len(current_df) == 0:
            logger.warning(f"Empty or invalid file: {current_file}")
            continue

        current_classified = apply_classification_functions(current_df.copy(), logger)

        # Count classifications
        for col in CLASSIFICATION_COLUMNS:
            if col in current_classified.columns:
                count = current_classified[col].sum()
                if count > 0:
                    logger.info(f"  {col}: {count} records")

        # Convert the classification columns to a IBR info
        current_classified = move_classification_columns_to_ibr_info(current_classified)

        # Save the file
        if current_file.name.endswith('.csv.gz'):
            output_name = current_file.name[:-7]
        else:
            output_name = current_file.name[:-4]

        output_path = dest_path / output_name
        save_dataframe(current_classified, output_path, compress, logger)

    logger.info("Processing complete!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='TCP Traffic Classifier',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        'source_dir',
        help='Directory containing input CSV files'
    )

    parser.add_argument(
        'dest_dir',
        help='Directory where output files will be saved'
    )

    parser.add_argument(
        '-g', '--no-gzip',
        action='store_true',
        help='Do not compress output files (default: compress with gzip)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose (debug) logging'
    )

    args = parser.parse_args()

    # Setup logger
    logger = setup_logger()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("TCP Traffic Classifier")
    logger.info("=" * 60)
    logger.info(f"Source directory: {args.source_dir}")
    logger.info(f"Destination directory: {args.dest_dir}")
    logger.info(f"Compression: {'disabled' if args.no_gzip else 'enabled (gzip)'}")
    logger.info("=" * 60)

    # Process files
    compress = not args.no_gzip
    process_files_with_sliding_window(
        args.source_dir,
        args.dest_dir,
        compress,
        logger
    )


if __name__ == '__main__':
    main()
