# 🛡️ CrowdStrike Firewall Toolkit

Tasked with migrating hundreds (thousands?) of Windows Firewall rules across many Windows Group Policies and having found no existing tools or scripts, I ended up creating my own. This toolkit includes scripts to convert, add, manage, and analyse firewall rules.

## Scripts Included

### 🔄 XML to CSV Script
- **WindowsFirewall_xml2csv.py**
  - A Python script to convert Windows Firewall Group Policy export XML file to CSV format for data manipulation and analysis.

### 📜 PowerShell Scripts
- **API_Add-Rules.ps1**
  - A PowerShell script to add firewall rules using the CrowdStrike API from CSV files.

- **API_WatchMode.ps1**
  - A PowerShell script to quickly bulk turn on/off Watch Mode on firewall rules.

### 📊 Log Analysis Scripts
- **summariseLogs.py**
  - A Python script to summarise exported CrowdStrike 'Firewall activity' CSV files into Inbound and Outbound firewall rule usage.

- **compareLogs.py**
  - A Python script to compare rules that have been added, deleted, or IP addresses added to existing rules from the summarised logs.

---
