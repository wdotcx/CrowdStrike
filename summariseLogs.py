#
# Description: Export CrowdStrike 'Firewall activity' results as csv, then this script will summarise the activity log into Inbound and Outbound firewall rule usage.
#              Keep the summaries for use with 'compareLogs.py'.
#
# Usage: python3 summariseLogs.py [file]
#        e.g. # python3 summariseLogs.py export.csv
#
# Requires: pandas ; pip install pandas
#
import pandas as pd
import re
import argparse
from datetime import datetime
import time

# Argument parsing
parser = argparse.ArgumentParser(description='Summarise CrowdStrike firewall csv export.')
parser.add_argument('csv_export', type=str, help='Path to CrowdStrike firewall csv export')
args = parser.parse_args()

# Load dataset
filePath = args.csv_export
data = pd.read_csv(filePath)

# Relevant columns
columns = ['ImageFileName', 'Protocol', 'RemoteAddress', 'RemotePort', 'LocalPort', 'ConnectionDirection', 'CommandLine']
csLog = data[columns].copy()

# Rename values in 'ImageFileName'
def renameImageFilename(filename):
    if not isinstance(filename, str):
        return filename
    filename = re.sub(r'\\Device\\HarddiskVolume\d+\\Windows\\', r'%SystemRoot%\\', filename)
    filename = re.sub(r'\\Device\\HarddiskVolume\d+\\', r'%SystemDrive%\\', filename)
    filename = re.sub(r'Users\\[^\\]+\\AppData', r'Users\\*\\AppData', filename)
    filename = re.sub(r'\\WindowsAzure\\[^\\]+\\', r'\\WindowsAzure\\*\\', filename)
    return filename

# Skip empty 'ImageFileName' rows
csLog = csLog[csLog['ImageFileName'].notna() & (csLog['ImageFileName'] != '')]
csLog['ImageFileName'] = csLog['ImageFileName'].astype(str).apply(renameImageFilename)

# Function; Extract service name as a new column 'Svc'
def extractServiceName(command_line):
    if not isinstance(command_line, str) or 'system32\\svchost.exe' not in command_line:
        return ''
    match = re.search(r'-s (\S+)', command_line)
    return match.group(1) if match else ''

csLog['CommandLine'] = csLog['CommandLine'].astype(str)
csLog['Svc'] = csLog['CommandLine'].apply(extractServiceName)

# Function; Move 'Svc' to the start
def reorderColumns(df):
    cols = list(df.columns)
    cols.remove('Svc')
    return df[['Svc'] + cols]


timestamp = time.strftime('%Y%m%dT%H%M%S', time.localtime())

# Process Outbound rules (ConnectionDirection == 0)
outboundRules = csLog[csLog['ConnectionDirection'] == 0]
if not outboundRules.empty:
    outboundGrouped = outboundRules.groupby(['ImageFileName', 'Protocol', 'RemotePort', 'Svc'])['RemoteAddress'] \
        .apply(lambda x: '; '.join(sorted(set(x), key=lambda ip: tuple(map(int, ip.split('.')))))) \
        .reset_index()
    # Reorder columns for outbound
    outboundGroupedReordered = reorderColumns(outboundGrouped)
    # Save outbound results
    outboundFilename = f'CSSum-Outbound-{timestamp}.csv'
    outboundGroupedReordered.to_csv(outboundFilename, index=False)
    print(f"Outbound rules saved to {outboundFilename}")

# Process Inbound rules (ConnectionDirection == 1)
inboundRules = csLog[csLog['ConnectionDirection'] == 1]
if not inboundRules.empty:
    inboundGrouped = inboundRules.groupby(['ImageFileName', 'Protocol', 'LocalPort', 'Svc'])['RemoteAddress'] \
        .apply(lambda x: '; '.join(sorted(set(x), key=lambda ip: tuple(map(int, ip.split('.')))))) \
        .reset_index()
    # Reorder columns for inbound
    inboundGroupedReordered = reorderColumns(inboundGrouped)
    # Save inbound results
    inboundFilename = f'CSSum-Inbound-{timestamp}.csv'
    inboundGroupedReordered.to_csv(inboundFilename, index=False)
    print(f"Inbound rules saved to {inboundFilename}")
