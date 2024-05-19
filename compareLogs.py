#
# Description: After generating firewall rule summaries with 'summariseLogs.py', compare rules that have been added, deleted, or IP addresses added to existing rules.
#              Typically you would have different daily summaries to compare firewall rule summaries.
#
# Usage: python3 compareLogsInbound.py [first] [updated]
#        e.g. # python3 compareLogsInbound.py CSSum-Outbound-20240519.csv CSSum-Outbound-20240521.csv
#
# Requires: pandas ; pip install pandas
#
import pandas as pd
import argparse
from datetime import datetime
import time

# Argument parsing
parser = argparse.ArgumentParser(description='Compare CrowdStrike firewall summaries.')
parser.add_argument('first', type=str, help='Path to the first csv file')
parser.add_argument('updated', type=str, help='Path to the updated csv file')
args = parser.parse_args()

# Load dataset
filePathFirst = args.first
filePathUpdated = args.updated
dataFirst = pd.read_csv(filePathFirst)
dataUpdated = pd.read_csv(filePathUpdated)

# Check for 'LocalPort' or 'RemotePort' column
if 'LocalPort' in dataFirst.columns and 'LocalPort' in dataUpdated.columns:
    portColumn = 'LocalPort'
    outputType = 'Inbound'
elif 'RemotePort' in dataFirst.columns and 'RemotePort' in dataUpdated.columns:
    portColumn = 'RemotePort'
    outputType = 'Outbound'
else:
    raise ValueError("Both files must contain either 'LocalPort' or 'RemotePort' column.")

# Relevant columns
columns = ['Svc', 'ImageFileName', 'Protocol', portColumn]

# Find added and deleted rows
addedRows = dataUpdated.merge(dataFirst, on=columns, how='left', indicator=True).query('_merge == "left_only"').drop(columns=['_merge'])
deletedRows = dataFirst.merge(dataUpdated, on=columns, how='left', indicator=True).query('_merge == "left_only"').drop(columns=['_merge'])

# Rename columns for added and deleted rows
addedRows = addedRows.rename(columns={'RemoteAddress_x': 'RemoteAddress'})
deletedRows = deletedRows.rename(columns={'RemoteAddress_y': 'RemoteAddress'})

# Find remaining rows to check RemoteAddress changes
firstRemainingRows = dataFirst.merge(dataUpdated, on=columns, how='inner', suffixes=('_original', '_diff'))

# Check for changes in RemoteAddress
remoteAddressChanges = firstRemainingRows[firstRemainingRows['RemoteAddress_original'] != firstRemainingRows['RemoteAddress_diff']]

# Function to find added and removed remote addresses
def findAddressChanges(row):
    originalAddresses = set(str(row['RemoteAddress_original']).split('; '))
    diffAddresses = set(str(row['RemoteAddress_diff']).split('; '))

    added = diffAddresses - originalAddresses
    removed = originalAddresses - diffAddresses

    return pd.Series({
        'RemoteAddress_add': '; '.join(added),
        'RemoteAddress_remove': '; '.join(removed)
    })

# Find changes
addressChanges = remoteAddressChanges.apply(findAddressChanges, axis=1)

# Concatenate the results
diffResults = pd.concat([remoteAddressChanges, addressChanges], axis=1)

# Add change identifiers
addedRows['ChangeType'] = 'Added'
deletedRows['ChangeType'] = 'Deleted'
diffResults['ChangeType'] = 'Modified'

# Update RemoteAddress for added and deleted rows
addedRows['RemoteAddress'] = addedRows['RemoteAddress']
deletedRows['RemoteAddress'] = deletedRows['RemoteAddress']

# Concatenate the results
combineResults = pd.concat([addedRows, deletedRows, diffResults], ignore_index=True)

# Ensure columns are in the correct order and fill NA
combineResults = combineResults[
    ['Svc', 'ImageFileName', 'Protocol', portColumn, 'RemoteAddress', 'RemoteAddress_original',
     'RemoteAddress_diff', 'RemoteAddress_add', 'RemoteAddress_remove', 'ChangeType']
].fillna('')


timestamp = time.strftime('%Y%m%dT%H%M%S', time.localtime())

# Save the combined DataFrame to a csv file
outputPath = f'CSCom-{outputType}-results-{timestamp}.csv'
combineResults.to_csv(outputPath, index=False)

print(f"Compare results saved to {outputPath}")
