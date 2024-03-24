#!/usr/bin/python3

#
# 'WindowsFirewall_xml2csv.py' Convert Windows Firewall Group Policy xml export to csv
#
import csv
import ipaddress
from xml.etree import ElementTree as ET
from functools import lru_cache

#
# Functions
#
@lru_cache(maxsize=None)
def Convert_ToCidr(subnet_mask):
    try:
        return str(ipaddress.IPv4Network(f'0.0.0.0/{subnet_mask}', strict=False).prefixlen)
    except ValueError:
        return subnet_mask

def IPSubnet_ToCidr(ip_subnet):
    try:
        ip, subnet_mask = ip_subnet.split('/')
        cidr = Convert_ToCidr(subnet_mask)
        return f'{ip}/{cidr}'
    except ValueError:
        return ip_subnet

def Get_Keys(rules):
    all_keys = set()
    for rule in rules:
        for element in rule:
            tag = element.tag.split('}', 1)[1]    # Remove namespace
            all_keys.add(tag)
    return all_keys

def Parse_FirewallRule(rule, all_keys):
    rule_data = {key: '' for key in all_keys}
    for element in rule:    # Iterate over child elements of the rule
        tag = element.tag.split('}', 1)[1]
        text = element.text.strip() if element.text else ''
        if tag in rule_data:    # Ensure we only use tags that are in our all_keys set
            if tag in ['RA4', 'LA4']:
                values = [IPSubnet_ToCidr(value) for value in text.split(';')]
                rule_data[tag] += ('; ' if rule_data[tag] else '') + '; '.join(values)
            else:
                rule_data[tag] += (', ' if rule_data[tag] else '') + text
    return rule_data

def Process_FirewallRules(import_file, rule_type, namespace):
    tree = ET.parse(import_file)
    root = tree.getroot()

    rules = root.findall(f".//{{{namespace}}}{rule_type}")
    all_keys = Get_Keys(rules)

    export_file = f"{rule_type}.csv"
    with open(export_file, 'w', newline='', encoding='utf-8') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=all_keys)
        dict_writer.writeheader()
        for rule in rules:
            rule_data = Parse_FirewallRule(rule, all_keys)
            dict_writer.writerow(rule_data)

    return export_file

#
# Main
#
if __name__ == "__main__":
    import_file = "example.xml"
    namespace = "http://www.microsoft.com/GroupPolicy/Settings/WindowsFirewall"

    inbound_rules = Process_FirewallRules(import_file, 'InboundFirewallRules', namespace)
    outbound_rules = Process_FirewallRules(import_file, 'OutboundFirewallRules', namespace)

    print(f"Inbound Firewall Rules exported to: {inbound_rules}")
    print(f"Outbound Firewall Rules exported to: {outbound_rules}")
