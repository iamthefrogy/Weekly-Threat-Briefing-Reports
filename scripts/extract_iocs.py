#!/usr/bin/env python3
"""
Extract IOCs from markdown reports and update IOCs.csv with strict filtering
and canonicalization.

Changes vs previous:
- Canonicalize all values (defanged [.] -> "." etc.) before writing CSV.
- Fix known case: dropbox-fileshare[.]net -> dropbox-fileshare.net (handled by canonicalizer).
- Ignore web asset extensions for domains/filenames (.html, .php, .js, .css, etc.).
- Validate IPv4 octets; drop invalid IPs.
- Rewrites IOCs.csv every run with canonical, deduped rows: Type,Value.
"""

from __future__ import annotations
import csv
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

# --- Locations ---
REPO_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = REPO_ROOT / "IOCs.csv"

# --- IOC Types ---
TYPE_DOMAIN = "Domain Name"
TYPE_IP = "IP"
TYPE_SHA256 = "SHA256"
TYPE_SHA1 = "SHA1"
TYPE_MD5 = "MD5"
TYPE_EMAIL = "Email Address"
TYPE_FILENAME = "Filename"

# --- Canonicalization helpers ---

def fang(s: str) -> str:
    """
    Convert common defanging to normal (fanged) for reliable dedup.
    - [.] -> .
    - (dot) -> .
    - [at] / (at) -> @
    - hxxp:// -> http:// (very conservative; not extracting URLs here, just domains/emails/IPs)
    """
    out = s
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("(dot)", ".")
    out = out.replace("[at]", "@").replace("(at)", "@")
    out = out.replace(" hxxp://", " http://").replace("hxxp://", "http://")
    out = out.replace(" hxxps://", " https://").replace("hxxps://", "https://")
    # Trim common trailing punctuation that sometimes clings to IOCs
    return out.strip("()[]{}<>,;\"' \t\r\n")

def is_valid_ipv4(ip: str) -> bool:
    """Strict IPv4 validation after fanging."""
    parts = fang(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= o <= 255 for o in octets)

# --- Regexes ---

HEX = r"[A-Fa-f0-9]"
RE_SHA256 = re.compile(rf"(?<![A-Fa-f0-9]){HEX}{{64}}(?![A-Fa-f0-9])")
RE_SHA1   = re.compile(rf"(?<![A-Fa-f0-9]){HEX}{{40}}(?![A-Fa-f0-9])")
RE_MD5    = re.compile(rf"(?<![A-Fa-f0-9]){HEX}{{32}}(?![A-Fa-f0-9])")

# IPv4 normal or defanged with [.] between octets
RE_IP = re.compile(
    r"\b(?:\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3})\b"
)

# Domains (defanged dot allowed). We later drop ones followed by forbidden file extensions.
# Also skip domains that are part of an email (preceded by '@').
RE_DOMAIN = re.compile(
    r"\b(?:(?:[A-Za-z0-9-]{1,63})(?:\[\.\]|\.)+)+[A-Za-z]{2,}\b"
)

# Emails
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Filenames (INTENTIONALLY excluding web assets like html/php/js/css)
ALLOWED_FILE_EXTS = (
    "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "pdf", "iso"
)
RE_FILENAME = re.compile(
    rf"\b[\w\-\s]+\.(?:{'|'.join(ALLOWED_FILE_EXTS)})\b",
    re.IGNORECASE,
)

FORBIDDEN_WEB_EXTS = (".html", ".htm", ".php", ".jsp", ".asp", ".aspx", ".js", ".css")

def looks_like_web_asset_after(text: str, end_idx: int) -> bool:
    """
    If immediately after a domain there's a path with a web-asset extension
    like /index.html, /a.js etc., signal that the match is a domain next to
    a web file path (which we still keep as a domain but we *don't* treat
    the file piece as domain or filename).
    This function helps to be explicit; domain regex already stops at the TLD.
    """
    # We don't need to drop the domain; the domain is correct.
    # We just return False because domain itself is okay.
    return False

def normalize(ioc_type: str, value: str) -> Tuple[str, str]:
    """
    Canonicalize for dedup & writing:
    - Domains lowercased, fanged.
    - IPs fanged.
    - Emails lowercased.
    - Filenames lowercased (keep original extension).
    """
    v = fang(value)
    if ioc_type == TYPE_DOMAIN:
        return (ioc_type, v.lower())
    if ioc_type == TYPE_EMAIL:
        return (ioc_type, v.lower())
    if ioc_type == TYPE_FILENAME:
        return (ioc_type, v.lower())
    if ioc_type == TYPE_IP:
        return (ioc_type, v)
    if ioc_type in (TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
        return (ioc_type, v.lower())
    return (ioc_type, v)

def strip_trailing_punct(s: str) -> str:
    return s.strip("()[]{}<>,;\"' \t\r\n")

def extract_from_text(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    # Work on a copy with common defang fixed for better detection
    t = fang(text)

    # Hashes
    out += [(TYPE_SHA256, m.group(0)) for m in RE_SHA256.finditer(t)]
    out += [(TYPE_SHA1,   m.group(0)) for m in RE_SHA1.finditer(t)]
    out += [(TYPE_MD5,    m.group(0)) for m in RE_MD5.finditer(t)]

    # IPs (then validate)
    for m in RE_IP.finditer(text):  # use original text to catch defanged forms, then fang
        raw = strip_trailing_punct(m.group(0))
        if is_valid_ipv4(raw):
            out.append((TYPE_IP, fang(raw)))

    # Emails
    for m in RE_EMAIL.finditer(t):
        out.append((TYPE_EMAIL, strip_trailing_punct(m.group(0))))

    # Domains (drop ones that are actually part of an email like "name@domain.com")
    for m in RE_DOMAIN.finditer(text):  # check original for defanged dots
        start = m.start()
        prev_char = text[start - 1] if start > 0 else " "
        if prev_char == "@":
            continue  # already captured as email
        dom = strip_trailing_punct(m.group(0))
        dom_fanged = fang(dom)

        # If someone wrote domain followed immediately by a path like /index.html,
        # we still keep the domain (regex stops at TLD). Just ensure it's not a "file".
        # Extra safety: refuse if the domain token itself ends with a web asset (rare).
        lower = dom_fanged.lower()
        if lower.endswith(FORBIDDEN_WEB_EXTS):
            continue  # don't treat *.html/php/js/css as domain

        out.append((TYPE_DOMAIN, dom_fanged))

    # Filenames (only allowed malware/doc/archive/iso types)
    for m in RE_FILENAME.finditer(t):
        fn = strip_trailing_punct(m.group(0))
        # Final safety: drop if filename ends with web asset (shouldn't happen due to regex)
        low = fn.lower()
        if low.endswith(FORBIDDEN_WEB_EXTS):
            continue
        out.append((TYPE_FILENAME, fn))

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
        yield path

def load_and_canonicalize_existing(csv_path: Path) -> List[Tuple[str, str]]:
    """Load existing CSV and canonicalize every row so legacy defanged values get fixed."""
    rows: List[Tuple[str, str]] = []
    if not csv_path.exists():
        return rows
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # skip header if present
        for line in reader:
            if not line or len(line) < 2:
                continue
            t, v = line[0].strip(), line[1].strip()
            t2, v2 = normalize(t, v)
            # Drop forbidden web assets from filenames/domains
            if t2 == TYPE_FILENAME and v2.lower().endswith(FORBIDDEN_WEB_EXTS):
                continue
            if t2 == TYPE_DOMAIN and v2.lower().endswith(FORBIDDEN_WEB_EXTS):
                continue
            # Validate IPs again after canonicalization
            if t2 == TYPE_IP and not is_valid_ipv4(v2):
                continue
            rows.append((t2, v2))
    return rows

def main(argv: List[str]) -> int:
    md_files = list(iter_markdown_files(argv))

    # 1) Load existing CSV and canonicalize all
    existing_rows = load_and_canonicalize_existing(CSV_PATH)

    # For deduplication, use a set of (Type, Value) after normalization
    seen: Set[Tuple[str, str]] = set(existing_rows)

    # 2) Extract from reports
    new_rows: List[Tuple[str, str]] = []
    for md in md_files:
        try:
            text = md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        found = extract_from_text(text)
        for ioc_type, value in found:
            key = normalize(ioc_type, value)
            # Filter again after normalize (e.g., bad IPs)
            t2, v2 = key
            if t2 == TYPE_IP and not is_valid_ipv4(v2):
                continue
            if t2 == TYPE_DOMAIN and v2.lower().endswith(FORBIDDEN_WEB_EXTS):
                continue
            if t2 == TYPE_FILENAME and v2.lower().endswith(FORBIDDEN_WEB_EXTS):
                continue
            if key not in seen:
                seen.add(key)
                new_rows.append(key)

    # 3) Merge and sort for stable output
    all_rows = existing_rows + new_rows
    if not all_rows:
        print("No IOCs found.")
        return 0

    all_rows_sorted = sorted(all_rows, key=lambda r: (r[0].lower(), r[1].lower()))

    # 4) Write back canonical, deduped CSV
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Type", "Value"])
        w.writerows(all_rows_sorted)

    print(f"Canonicalized + added {len(new_rows)} new IOCs. Total rows: {len(all_rows_sorted)}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
