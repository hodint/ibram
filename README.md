# IBRAM 

This repository includes all the scripts for demonstrating the IBRAM methodology for analysing IBR traffic.
Each directory includes its own README file detailing each of the steps in that environment.

## Directories

This section shows the directories and how to use them.

- 01_pcap_tools: This directory contains the scripts for preparing the acquired PCAP files for analysis.

The following directories are used to generate statistics in PCAP files for the article, and are not necessary for the IBRAM methodology:

- 02_pcap_stats: This directory includes scripts to calculate statistics on PCAP files.
- 03_pcap_conversations: This directory contains scripts to extract conversations from PCAP files.

At this point, the PCAP files will be ready for analysis with IBRAM, obtained from the 01_pcap_tools directory process. The main point is to use the division of PCAP files into time intervals, which is done with the scripts `pcap_split_chunks.py` + `pcap_split_days.sh` so as not to have performance or memory exhaustion problems in subsequent processes.

- 04_convert_to_text: This folder includes the scripts to convert the PCAP files into text formats for further analysis. The input for these scripts are the PCAP files obtained from the previous step. The main script is `01_pcap_to_csvtshark.py`, which uses `tshark` to convert the PCAP files into CSV format. After obtaining the CSV files, the `02_csvtshark_to_csvmod.py` script can be used to process the CSV files further.
- 05_ip_reassembly: This directory contains scripts to reassemble fragmented IP packets from CSV files generated in the previous step.
