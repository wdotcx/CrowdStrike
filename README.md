# CrowdStrike
One day the CTO purchased a CrowdStrike enterprise agreement because he saw CrowdStrike was in the top right Gartner Magic Quadrant.

I was tasked with migrating hundreds (thousands?) of Windows Firewall rules across many Windows Group Policies. Having found no existing tools or scripts I ended up creating my own. Hopefully, this will save another poor security administrator some time when C levels make these decisions.

- WindowsFirewall_xml2csv.py - Python script to convert Windows Firewall Group Policy export xml to csv
- API_Add-Rules.ps1 - PowerShell script to add firewall rules using CrowdStrike API from csv
