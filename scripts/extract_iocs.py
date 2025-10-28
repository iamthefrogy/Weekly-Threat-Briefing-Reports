#!/usr/bin/env python3
"""
Extract IOCs from markdown reports and update IOCs.csv with deduplication.

Usage:
  python scripts/extract_iocs.py [optional list of changed .md files]

Behavior:
  - If file args provided: only scan those that exist and end with .md
  - Else: recursively scan all *.md files under the repo
  - Write/append to IOCs.csv in repo root with Type,Value (deduped)
"""

from __future__ import annotations
import csv
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

# --- Configuration ---
REPO_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = REPO_ROOT / "IOCs.csv"

# IOC Types
TYPE_DOMAIN = "Domain Name"
TYPE_IP = "IP"
TYPE_SHA256 = "SHA256"
TYPE_SHA1 = "SHA1"
TYPE_MD5 = "MD5"
TYPE_EMAIL = "Email Address"
TYPE_FILENAME = "Filename"

# Regex patterns (designed to catch defanged forms too)
HEX = r"[A-Fa-f0-9]"
RE_SHA256 = re.compile(rf"\b{HEX}{{64}}\b")
RE_SHA1 = re.compile(rf"\b{HEX}{{40}}\b")
RE_MD5 = re.compile(rf"\b{HEX}{{32}}\b")

# IPv4 (both normal and defanged with [.] ), then validate octets later
RE_IP = re.compile(
    r"\b(?:\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3})\b"
)

# Domains:
# - allow labels separated by "." or "[.]" and require a final TLD (2+ letters)
# - try to avoid matching pure IP addresses or markdown artifacts
RE_DOMAIN = re.compile(
    r"\b(?:(?:[A-Za-z0-9-]{1,63})(?:\[\.\]|\.)+)+[A-Za-z]{2,}\b"
)

# Emails (simple, practical)
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Filenames of interest
RE_FILENAME = re.compile(
    r"\b[\w\-\s]+\.(?:exe|dll|docx|doc|xls|xlsx|ppt|pptx|zip|rar|7z|pdf|html|js|vbs|ps1|bat|iso)\b",
    re.IGNORECASE,
)

def fang(s: str) -> str:
    """Convert defanged [.] to . (for normalization)."""
    return s.replace("[.]", ".")

def is_valid_ipv4(ip: str) -> bool:
    """Validate IPv4 string (works for fanged or defanged)."""
    parts = fang(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= o <= 255 for o in octets)

def normalize_entry(ioc_type: str, value: str) -> Tuple[str, str]:
    """
    Build a normalized key for deduplication.
    - Domains, emails, filenames: lower + fanged
    - IP: fanged exact
    - Hashes: lower
    """
    v = value.strip()
    if ioc_type == TYPE_DOMAIN:
        return (ioc_type, fang(v).lower())
    if ioc_type == TYPE_EMAIL:
        return (ioc_type, v.lower())
    if ioc_type == TYPE_FILENAME:
        return (ioc_type, v.lower())
    if ioc_type == TYPE_IP:
        return (ioc_type, fang(v))
    if ioc_type in (TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
        return (ioc_type, v.lower())
    return (ioc_type, v)

def load_existing(csv_path: Path) -> Tuple[List[Tuple[str, str]], Set[Tuple[str, str]]]:
    rows: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    if not csv_path.exists():
        return rows, seen

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        # tolerate missing/extra header as long as there are two columns
        for line in reader:
            if not line:
                continue
            if len(line) < 2:
                continue
            ioc_type, value = line[0].strip(), line[1].strip()
            rows.append((ioc_type, value))
            seen.add(normalize_entry(ioc_type, value))
    return rows, seen

def extract_from_text(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []

    # Hashes
    for m in RE_SHA256.findall(text):
        out.append((TYPE_SHA256, m))
    for m in RE_SHA1.findall(text):
        out.append((TYPE_SHA1, m))
    for m in RE_MD5.findall(text):
        out.append((TYPE_MD5, m))

    # IPs (filter invalid)
    for m in RE_IP.findall(text):
        if is_valid_ipv4(m):
            out.append((TYPE_IP, m))

    # Emails
    for m in RE_EMAIL.findall(text):
        out.append((TYPE_EMAIL, m))

    # Domains (filter out bare IP-like)
    for m in RE_DOMAIN.findall(text):
        # If it's actually an IP shape, skip (already captured as IP)
        if is_valid_ipv4(m):
            continue
        out.append((TYPE_DOMAIN, m))

    # Filenames
    for m in RE_FILENAME.findall(text):
        out.append((TYPE_FILENAME, m))

    return out

def iter_markdown_files(args: List[str]) -> Iterable[Path]:
    # If changed files were passed from the workflow, use those
    if args:
        for p in args:
            path = REPO_ROOT / p if not p.startswith("/") else Path(p)
            if path.suffix.lower() == ".md" and path.exists():
                yield path
        return

    # Else, recursively scan all .md files
    for path in REPO_ROOT.rglob("*.md"):
        # Skip files in .github/ or other non-report locations if desired:
        # if ".github" in path.parts: continue
        yield path

def main(argv: List[str]) -> int:
    md_files = list(iter_markdown_files(argv))

    # Read existing CSV & seen keys
    existing_rows, seen = load_existing(CSV_PATH)

    new_rows: List[Tuple[str, str]] = []

    for md in md_files:
        try:
            text = md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        found = extract_from_text(text)
        for ioc_type, value in found:
            key = normalize_entry(ioc_type, value)
            if key not in seen:
                seen.add(key)
                # Preserve original matched form (defanged stays defanged)
                new_rows.append((ioc_type, value))

    # If nothing new, exit quietly
    if not new_rows:
        print("No new IOCs found.")
        return 0

    # Merge and write back, sorted for stability
    all_rows = existing_rows + new_rows
    # Optional: stable sort by (Type, Value) case-insensitive
    all_rows_sorted = sorted(all_rows, key=lambda r: (r[0].lower(), r[1].lower()))

    # Ensure header
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Value"])
        writer.writerows(all_rows_sorted)

    print(f"Added {len(new_rows)} new IOCs. Total rows: {len(all_rows_sorted)}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
