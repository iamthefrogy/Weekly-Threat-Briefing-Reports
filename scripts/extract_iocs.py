#!/usr/bin/env python3
import json
import os
import re
import csv
from collections import OrderedDict

# Regex patterns for different IOCs (defanged variants included)
DOMAIN_RE = re.compile(r"(?i)([a-z0-9.-]+\[\.\]|[a-z0-9.-]+\.)+[a-z]{2,}")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3})\b")
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
FILENAME_RE = re.compile(r"\b[\w.-]+\.(?:exe|dll|docx|pdf|zip|html)\b", re.IGNORECASE)

# Normalise domains (remove [.] and trailing backticks)
def refang_domain(d):
    return d.replace('[.]', '.').strip('`').lower()

# Load list of changed files from GitHub event
with open(os.environ['GITHUB_EVENT_PATH']) as f:
    event = json.load(f)
changed_files = event['head_commit'].get('added', []) + event['head_commit'].get('modified', [])
report_files = [f for f in changed_files if f.endswith('.md') and f.lower() != 'readme.md']

# Read existing CSV into a set for deduplication
existing = set()
if os.path.exists('IOCs.csv'):
    with open('IOCs.csv', newline='', encoding='utf-8') as csvfile:
        for row in csv.reader(csvfile):
            if row and row[0] != 'Type':
                existing.add((row[0], row[1].lower()))

new_iocs = []
for report in report_files:
    with open(report, encoding='utf-8') as f:
        content = f.read()
    # Find the IOC section
    ioc_section = ''
    marker = 'Indicators of Compromise'
    start = content.lower().find(marker.lower())
    if start != -1:
        # get everything after heading until next heading
        after = content[start:]
        # stop at the next ‘### ’ or ‘---’
        stop = len(after)
        for delim in ['\n### ', '\n## ', '\n* * *']:
            idx = after.find(delim)
            if idx > 0:
                stop = min(stop, idx)
        ioc_section = after[:stop]
    else:
        ioc_section = content  # fallback: search whole file

    # Extract indicators
    for match in DOMAIN_RE.findall(ioc_section):
        domain = refang_domain(match)
        if ("Domain Name", domain) not in existing:
            existing.add(("Domain Name", domain))
            new_iocs.append(("Domain Name", domain))
    for match in IP_RE.findall(ioc_section):
        ip = match.replace('[.]', '.').strip('`')
        if ("IP", ip) not in existing:
            existing.add(("IP", ip))
            new_iocs.append(("IP", ip))
    for match in SHA256_RE.findall(ioc_section):
        val = match.lower()
        if ("SHA256", val) not in existing:
            existing.add(("SHA256", val))
            new_iocs.append(("SHA256", val))
    for match in MD5_RE.findall(ioc_section):
        val = match.lower()
        if ("MD5", val) not in existing:
            existing.add(("MD5", val))
            new_iocs.append(("MD5", val))
    for match in EMAIL_RE.findall(ioc_section):
        email = match.lower()
        if ("Email Address", email) not in existing:
            existing.add(("Email Address", email))
            new_iocs.append(("Email Address", email))
    for match in FILENAME_RE.findall(ioc_section):
        name = match
        if ("Filename", name) not in existing:
            existing.add(("Filename", name))
            new_iocs.append(("Filename", name))

# Update the CSV
if new_iocs:
    # Combine all entries (existing + new), sort by type then value
    all_rows = list(existing)
    all_rows.sort(key=lambda x: (x[0], x[1]))
    with open('IOCs.csv', 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type', 'Value'])
        for row in all_rows:
            writer.writerow(row)
else:
    print("No new IOCs found")
