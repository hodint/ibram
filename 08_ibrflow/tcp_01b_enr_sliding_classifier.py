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
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

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

# Window configuration (in hours)
WINDOW_SIZE_HOURS = 24
WINDOW_SLIDE_HOURS = 12


def setup_logger() -> logging.Logger:
    """Configure and return the logger."""
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logger


def get_sorted_files(source_dir: str, logger: logging.Logger) -> List[Path]:
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


def get_time_boundaries(df: pd.DataFrame) -> Tuple[datetime, datetime]:
    """Get the minimum and maximum timestamps from the dataframe."""
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    return df['timestamp'].min(), df['timestamp'].max()


def filter_by_time_range(
    df: pd.DataFrame,
    start_time: datetime,
    end_time: datetime
) -> pd.DataFrame:
    """Filter dataframe to only include records within the time range."""
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    mask = (df['timestamp'] >= start_time) & (df['timestamp'] < end_time)
    return df[mask].copy()  # type: ignore


def merge_classification_results(
    base_df: pd.DataFrame,
    new_df: pd.DataFrame,
    logger: logging.Logger
) -> pd.DataFrame:
    """
    Merge classification results using OR logic for boolean columns.

    Records are matched by the 'key' column (unique identifier).
    Uses vectorized pandas operations for efficiency.
    """
    if base_df is None or len(base_df) == 0:
        return new_df.copy()

    if new_df is None or len(new_df) == 0:
        return base_df.copy()

    # Get classification columns that exist in both dataframes
    existing_cols = [col for col in CLASSIFICATION_COLUMNS if col in base_df.columns and col in new_df.columns]

    if not existing_cols:
        logger.warning("No classification columns found to merge")
        return base_df

    # Log counts BEFORE merge
    logger.info("  Classification counts BEFORE merge:")
    before_counts = {}
    for col in existing_cols:
        count = base_df[col].sum()
        before_counts[col] = count
        if count > 0:
            logger.info(f"    {col}: {count}")

    # Find common keys
    common_keys = set(base_df['key']).intersection(set(new_df['key']))

    if len(common_keys) == 0:
        logger.debug("No overlapping records to merge")
        return base_df.copy()

    logger.debug(f"Merging {len(common_keys)} overlapping records using vectorized operations")

    # Create a subset of new_df with only the columns we need for merging
    merge_cols = ['key'] + existing_cols
    new_df_subset = new_df[merge_cols].copy()

    # Rename classification columns in new_df to avoid conflicts
    rename_dict = {col: f"{col}_new" for col in existing_cols}
    new_df_subset = new_df_subset.rename(columns=rename_dict) # type: ignore

    # Merge using pandas (much faster than row-by-row)
    result_df = base_df.merge(new_df_subset, on='key', how='left')

    # Apply OR logic for each classification column
    for col in existing_cols:
        new_col = f"{col}_new"
        # Fill NaN with False for the new column (records not in new_df)
        result_df[new_col] = result_df[new_col].fillna(False).astype(bool)
        # OR logic: True if either is True
        result_df[col] = result_df[col] | result_df[new_col]
        # Drop the temporary column
        result_df = result_df.drop(columns=[new_col])

    # Log counts AFTER merge
    logger.info("  Classification counts AFTER merge:")
    for col in existing_cols:
        count = result_df[col].sum()
        diff = count - before_counts[col]
        if count > 0 or diff != 0:
            diff_str = f" (+{diff})" if diff > 0 else (f" ({diff})" if diff < 0 else "")
            logger.info(f"    {col}: {count}{diff_str}")

    return result_df


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
    Process files using sliding window approach.

    Strategy:
    1. Load Day N
    2. Classify full 24h of Day N
    3. Load Day N+1
    4. Classify last 12h of Day N + first 12h of Day N+1
    5. Merge results for Day N (OR logic)
    6. Save Day N, free memory
    7. Classify full 24h of Day N+1
    8. Repeat from step 3
    """
    # Get sorted list of files
    files = get_sorted_files(source_dir, logger)

    # Create destination directory if it doesn't exist
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    # Track processed data
    prev_day_df: Optional[pd.DataFrame] = None
    prev_day_file: Optional[Path] = None
    prev_day_results: Optional[pd.DataFrame] = None
    prev_day_mid_time: Optional[datetime] = None

    for i, current_file in enumerate(files):
        logger.info(f"Processing file {i+1}/{len(files)}: {current_file.name}")

        # Load current day
        current_df = load_file(str(current_file), logger)

        if current_df is None or len(current_df) == 0:
            logger.warning(f"Empty or invalid file: {current_file}")
            continue

        # Ensure timestamp is datetime
        current_df['timestamp'] = pd.to_datetime(current_df['timestamp'])

        # Get time boundaries for current day
        current_min_time, current_max_time = get_time_boundaries(current_df)
        current_mid_time = current_min_time + timedelta(hours=WINDOW_SLIDE_HOURS)

        logger.debug(f"Current day time range: {current_min_time} to {current_max_time}")

        # === STEP 1: Process overlap window (last 12h of prev + first 12h of current) ===
        if prev_day_df is not None and prev_day_mid_time is not None:
            logger.info("Processing overlap window (previous day end + current day start)...")

            # Get last 12 hours of previous day
            prev_last_12h = filter_by_time_range(
                prev_day_df,
                prev_day_mid_time,
                prev_day_mid_time + timedelta(hours=WINDOW_SIZE_HOURS)
            )

            # Get first 12 hours of current day
            current_first_12h = filter_by_time_range(
                current_df,
                current_min_time,
                current_mid_time
            )

            # Combine for overlap window
            overlap_window = pd.concat([prev_last_12h, current_first_12h], ignore_index=True)

            if len(overlap_window) > 0:
                logger.info(f"Overlap window: {len(overlap_window)} records")

                # Apply classification to overlap window
                overlap_classified = apply_classification_functions(overlap_window.copy(), logger)

                # Extract results for previous day (last 12h)
                prev_overlap_results = filter_by_time_range(
                    overlap_classified,
                    prev_day_mid_time,
                    prev_day_mid_time + timedelta(hours=WINDOW_SIZE_HOURS)
                )

                # Merge with previous day results
                if prev_day_results is not None:
                    prev_day_results = merge_classification_results(
                        prev_day_results,
                        prev_overlap_results,
                        logger
                    )

                # Extract results for current day first 12h (to be used later)
                current_first_12h_results = filter_by_time_range(
                    overlap_classified,
                    current_min_time,
                    current_mid_time
                )
            else:
                current_first_12h_results = None

            # === STEP 2: Save previous day results ===
            if prev_day_results is not None and prev_day_file is not None:
                output_name = prev_day_file.stem
                if output_name.endswith('.csv'):
                    output_name = output_name[:-4]
                output_path = dest_path / output_name
                prev_day_results = move_classification_columns_to_ibr_info(prev_day_results)
                save_dataframe(prev_day_results, output_path, compress, logger)

                # Free memory
                del prev_day_results
                del prev_day_df
                prev_day_results = None
                prev_day_df = None
        else:
            current_first_12h_results = None

        # === STEP 3: Process full current day (24h window) ===
        logger.info("Processing full day window (24h)...")
        current_classified = apply_classification_functions(current_df.copy(), logger)

        # Count classifications
        for col in CLASSIFICATION_COLUMNS:
            if col in current_classified.columns:
                count = current_classified[col].sum()
                if count > 0:
                    logger.info(f"  {col}: {count} records")

        # === STEP 4: Merge with first 12h overlap results ===
        if current_first_12h_results is not None:
            current_classified = merge_classification_results(
                current_classified,
                current_first_12h_results,
                logger
            )

        # === STEP 5: Prepare for next iteration ===
        prev_day_df = current_df
        prev_day_file = current_file
        prev_day_results = current_classified
        prev_day_mid_time = current_mid_time

    # === FINAL: Save the last day ===
    if prev_day_results is not None and prev_day_file is not None:
        logger.info("Saving final day...")
        output_name = prev_day_file.stem
        if output_name.endswith('.csv'):
            output_name = output_name[:-4]
        output_path = dest_path / output_name
        prev_day_results = move_classification_columns_to_ibr_info(prev_day_results)
        save_dataframe(prev_day_results, output_path, compress, logger)

    logger.info("Processing complete!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='TCP Traffic Classifier with Sliding Windows',
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
    logger.info("TCP Traffic Classifier with Sliding Windows")
    logger.info("=" * 60)
    logger.info(f"Source directory: {args.source_dir}")
    logger.info(f"Destination directory: {args.dest_dir}")
    logger.info(f"Compression: {'disabled' if args.no_gzip else 'enabled (gzip)'}")
    logger.info(f"Window size: {WINDOW_SIZE_HOURS} hours")
    logger.info(f"Window slide: {WINDOW_SLIDE_HOURS} hours")
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
