#!/usr/bin/env python3
"""
Extract IOCs only from Section "4. Indicators of Compromise (IOCs)" in report .md files,
and update IOCs.csv with:
  - Minimum columns: Type, Value
  - Plus any extra columns present in the section's table (union across all reports)
Features:
  - Canonicalize values: defanged [.] -> ., (at) -> @, lowercasing where appropriate
  - Validate IPv4; drop invalid addresses
  - Ignore web-asset suffixes for domains/filenames: .html, .htm, .php, .jsp, .asp, .aspx, .js, .css
  - Deduplicate by (Type,Value) after canonicalization
  - Merge rows for the same (Type,Value): keep the most complete set of extra columns
  - Supports 2 formats inside Section 4:
      (1) Proper Markdown pipe tables
      (2) Simple "lines" where each row begins with IOC Type followed by its value
"""

from __future__ import annotations
import csv
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Set

# ---------- Paths ----------
REPO_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = REPO_ROOT / "IOCs.csv"

# ---------- IOC Types ----------
TYPE_DOMAIN = "Domain Name"
TYPE_IP = "IP"
TYPE_SHA256 = "SHA256"
TYPE_SHA1 = "SHA1"
TYPE_MD5 = "MD5"
TYPE_EMAIL = "Email Address"
TYPE_FILENAME = "Filename"

MIN_COLUMNS = [TYPE_DOMAIN, TYPE_IP, TYPE_SHA256, TYPE_SHA1, TYPE_MD5, TYPE_EMAIL, TYPE_FILENAME]  # for detection
MANDATORY_OUTPUT = ["Type", "Value"]

FORBIDDEN_WEB_EXTS = (".html", ".htm", ".php", ".jsp", ".asp", ".aspx", ".js", ".css")
ALLOWED_FILE_EXTS = (
    "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "pdf", "iso"
)

# ---------- Canonicalization ----------
def fang(s: str) -> str:
    """Defang -> fang; trim common wrappers."""
    out = s
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("(dot)", ".")
    out = out.replace("[at]", "@").replace("(at)", "@")
    out = out.replace(" hxxp://", " http://").replace("hxxp://", "http://")
    out = out.replace(" hxxps://", " https://").replace("hxxps://", "https://")
    return out.strip("()[]{}<>,;\"' \t\r\n")

def is_valid_ipv4(ip: str) -> bool:
    parts = fang(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= o <= 255 for o in octets)

def normalize_value(ioc_type: str, value: str) -> str:
    v = fang(value)
    if ioc_type in (TYPE_DOMAIN, TYPE_EMAIL, TYPE_FILENAME, TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
        v = v.lower()
    return v

def endswith_forbidden_web_ext(s: str) -> bool:
    low = s.lower()
    return any(low.endswith(ext) for ext in FORBIDDEN_WEB_EXTS)

# ---------- Regexes for picking up IOCs when not in pipe-table ----------
HEX = r"[A-Fa-f0-9]"
RE_SHA256 = re.compile(rf"(?<![A-Fa-f0-9]){HEX}{{64}}(?![A-Fa-f0-9])")
RE_SHA1   = re.compile(rf"(?<![A-Fa-f0-9]){HEX}{{40}}(?![A-Fa-f0-9])")
RE_MD5    = re.compile(rf"(?<![A-Fa-f0-9]){HEX}{{32}}(?![A-Fa-f0-9])")

RE_IP_DEFANGED = re.compile(
    r"\b(?:\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3})\b"
)
RE_DOMAIN = re.compile(
    r"\b(?:(?:[A-Za-z0-9-]{1,63})(?:\[\.\]|\.)+)+[A-Za-z]{2,}\b"
)
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
RE_FILENAME = re.compile(
    rf"\b[\w\-\s]+\.(?:{'|'.join(ALLOWED_FILE_EXTS)})\b",
    re.IGNORECASE,
)

# ---------- Section extraction ----------
HEADING_4_RE = re.compile(
    r"^\s*#{2,6}\s*4\.\s*Indicators of Compromise\s*\(IOCs\)\s*$",
    re.IGNORECASE | re.MULTILINE
)
NEXT_HEADING_RE = re.compile(r"^\s*#{2,6}\s+\d+\.", re.MULTILINE)

def extract_section_4(md_text: str) -> str:
    """
    Return only the text content under "### 4. Indicators of Compromise (IOCs)"
    up to (but not including) the next heading like '### 5.' or any next heading number.
    """
    m = HEADING_4_RE.search(md_text)
    if not m:
        return ""
    start = m.end()
    # Look for next numbered heading (### 5. ... or similar)
    m2 = NEXT_HEADING_RE.search(md_text, start)
    end = m2.start() if m2 else len(md_text)
    return md_text[start:end].strip()

# ---------- Markdown pipe-table parsing ----------
def parse_pipe_tables(block: str) -> List[Dict[str, str]]:
    """
    Parse GitHub-flavored Markdown tables in the provided block.
    Returns list of dict rows with column names normalized (strip).
    """
    lines = [ln.rstrip() for ln in block.splitlines()]
    rows: List[Dict[str, str]] = []

    i = 0
    while i < len(lines):
        # A table typically has two+ lines starting with '|' and second is a separator with ---.
        if "|" in lines[i].strip().lstrip("|"):
            # try to detect header
            header_line = lines[i].strip()
            # find separator on next non-empty line
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines) and re.search(r"\|\s*:?-{3,}", lines[j]):
                # We have a table
                headers = [h.strip() for h in header_line.strip("|").split("|")]
                # advance past separator
                j += 1
                # consume body rows until a non-table line
                while j < len(lines) and "|" in lines[j]:
                    row_vals = [c.strip() for c in lines[j].strip().strip("|").split("|")]
                    # pad/truncate to headers length
                    if len(row_vals) < len(headers):
                        row_vals += [""] * (len(headers) - len(row_vals))
                    elif len(row_vals) > len(headers):
                        row_vals = row_vals[:len(headers)]
                    row = dict(zip(headers, row_vals))
                    rows.append(row)
                    j += 1
                i = j
                continue
        i += 1
    return rows

# ---------- Fallback loose-line parsing inside Section 4 ----------
def parse_loose_lines(block: str) -> List[Dict[str, str]]:
    """
    Handle simpler bullet/line formats inside the section, e.g.:
      Domain `inspectguarantee[.]org` May 2025 Current ...
      SHA256 `abc...` ...
    We reliably capture at least Type, Value.
    """
    rows: List[Dict[str, str]] = []
    for raw in block.splitlines():
        line = raw.strip()
        if not line or line.startswith(("*", "-", ">")):
            # Might still contain indicators in description lines, but to keep it precise,
            # only parse lines that *start* with a known type.
            pass
        # Prefer a clear "Type `value`" pattern
        m = re.match(r"^(Domain|Domain Name|IP|SHA256|SHA1|MD5|Email|Email Address|Filename)\s+`?([^`\s]+)`?(.*)$", line, re.IGNORECASE)
        if not m:
            continue
        type_token = m.group(1).lower()
        value_token = m.group(2).strip()

        # Normalize type name to our standard labels
        if type_token in ("domain", "domain name"):
            ioc_type = TYPE_DOMAIN
        elif type_token == "ip":
            ioc_type = TYPE_IP
        elif type_token == "sha256":
            ioc_type = TYPE_SHA256
        elif type_token == "sha1":
            ioc_type = TYPE_SHA1
        elif type_token == "md5":
            ioc_type = TYPE_MD5
        elif type_token in ("email", "email address"):
            ioc_type = TYPE_EMAIL
        elif type_token == "filename":
            ioc_type = TYPE_FILENAME
        else:
            continue

        # Validate/clean value
        val = value_token
        if ioc_type == TYPE_IP:
            if not is_valid_ipv4(val):
                # try defanged in remainder:
                m_ip = RE_IP_DEFANGED.search(value_token)
                if not m_ip or not is_valid_ipv4(m_ip.group(0)):
                    continue
                val = fang(m_ip.group(0))
        elif ioc_type == TYPE_DOMAIN:
            # extract first domain-like token
            m_dom = RE_DOMAIN.search(value_token) or RE_DOMAIN.search(" " + value_token)
            if m_dom:
                val = fang(m_dom.group(0))
                if endswith_forbidden_web_ext(val):
                    continue
            else:
                continue
        elif ioc_type == TYPE_EMAIL:
            m_em = RE_EMAIL.search(value_token)
            if m_em:
                val = m_em.group(0)
            else:
                continue
        elif ioc_type == TYPE_FILENAME:
            # allow only certain extensions
            m_fn = RE_FILENAME.search(value_token)
            if m_fn:
                val = m_fn.group(0)
                if endswith_forbidden_web_ext(val):
                    continue
            else:
                continue
        elif ioc_type in (TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
            # hashes from remainder or value token itself
            m_hash = None
            if ioc_type == TYPE_MD5:
                m_hash = RE_MD5.search(value_token)
            elif ioc_type == TYPE_SHA1:
                m_hash = RE_SHA1.search(value_token)
            else:
                m_hash = RE_SHA256.search(value_token)
            if m_hash:
                val = m_hash.group(0)
            else:
                # if token already looks like hash, accept it
                if not (
                    (ioc_type == TYPE_MD5 and RE_MD5.fullmatch(value_token)) or
                    (ioc_type == TYPE_SHA1 and RE_SHA1.fullmatch(value_token)) or
                    (ioc_type == TYPE_SHA256 and RE_SHA256.fullmatch(value_token))
                ):
                    continue

        rows.append({"Type": ioc_type, "Value": val})
    return rows

# ---------- CSV helpers ----------
def load_existing_and_canonicalize(csv_path: Path) -> Tuple[List[Dict[str, str]], Dict[Tuple[str, str], Dict[str, str]]]:
    """
    Load existing CSV, canonicalize all values (fix defanging, case, invalids),
    return list of rows and an index map by (Type,Value).
    """
    rows: List[Dict[str, str]] = []
    index: Dict[Tuple[str, str], Dict[str, str]] = {}
    if not csv_path.exists():
        return rows, index

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            t = row.get("Type", "").strip()
            v = row.get("Value", "").strip()
            if not t or not v:
                continue
            v_norm = normalize_value(t, v)
            # Validate filters
            if t == TYPE_IP and not is_valid_ipv4(v_norm):
                continue
            if t == TYPE_DOMAIN and endswith_forbidden_web_ext(v_norm):
                continue
            if t == TYPE_FILENAME and endswith_forbidden_web_ext(v_norm):
                continue

            # Canonicalize row fields
            row_canon = {k: (normalize_value(t, v) if k == "Value" else v2) for k, v2 in row.items()}
            row_canon["Type"] = t  # keep canonical label
            row_canon["Value"] = v_norm

            key = (t, v_norm)
            prev = index.get(key)
            if prev:
                # Merge: keep fields that are non-empty; prefer longer value text if conflict
                for k, v2 in row_canon.items():
                    if k in ("Type", "Value"):
                        continue
                    if v2 and not prev.get(k):
                        prev[k] = v2
            else:
                index[key] = row_canon
                rows.append(row_canon)
    return rows, index

def union_headers(existing_headers: List[str], new_headers: List[str]) -> List[str]:
    out = existing_headers[:]
    for h in new_headers:
        if h not in out:
            out.append(h)
    return out

# ---------- Main extraction ----------
def iter_markdown_files(args: List[str]) -> Iterable[Path]:
    if args:
        for p in args:
            path = REPO_ROOT / p if not p.startswith("/") else Path(p)
            if path.suffix.lower() == ".md" and path.exists():
                yield path
        return
    # else scan all
    for p in REPO_ROOT.rglob("*.md"):
        yield p

def main(argv: List[str]) -> int:
    # Load and canonicalize existing CSV
    existing_rows, index = load_existing_and_canonicalize(CSV_PATH)
    # Build header union (start with mandatory)
    header: List[str] = ["Type", "Value"]
    for r in existing_rows:
        header = union_headers(header, [h for h in r.keys() if h not in header])

    # Process markdowns passed from workflow (or all)
    md_files = list(iter_markdown_files(argv))
    new_or_updated = 0

    for md in md_files:
        try:
            text = md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        sec = extract_section_4(text)
        if not sec:
            continue

        # First, try to parse pipe tables to collect rich columns.
        table_rows = parse_pipe_tables(sec)
        parsed_any = False

        for tr in table_rows:
            # Normalize header names: strip, collapse spaces
            norm = { (k or "").strip(): (v or "").strip() for k, v in tr.items() }
            # Require at least Type and a value-like column
            # Try common column names for value
            # (The sample shows "Type Value First Seen (UTC)...")
            keys = list(norm.keys())
            if "Type" not in norm:
                continue

            # Find the column holding the IOC value
            value_col = None
            for cand in ["Value", "Indicator", "IOC", "Indicator Value"]:
                if cand in norm and norm[cand]:
                    value_col = cand
                    break
            if not value_col:
                # Heuristic: if there's a column with a domain/IP/hash-looking token, use it
                for k in keys:
                    if k.lower() in ("type",):
                        continue
                    if norm.get(k):
                        value_col = k
                        break
            if not value_col:
                continue

            ioc_type = norm["Type"].strip()
            # Canonicalize label
            lower = ioc_type.lower()
            if lower in ("domain", "domain name"):
                ioc_type = TYPE_DOMAIN
            elif lower == "ip":
                ioc_type = TYPE_IP
            elif lower == "sha256":
                ioc_type = TYPE_SHA256
            elif lower == "sha1":
                ioc_type = TYPE_SHA1
            elif lower == "md5":
                ioc_type = TYPE_MD5
            elif lower in ("email", "email address"):
                ioc_type = TYPE_EMAIL
            elif lower == "filename":
                ioc_type = TYPE_FILENAME
            else:
                # Unknown type — skip
                continue

            raw_val = norm.get(value_col, "")
            if not raw_val:
                continue

            # Try to extract a clean value from the cell (could contain backticks or text)
            val = raw_val.strip("` ").strip()
            # If the cell includes extra words, try more precise extractors
            if ioc_type == TYPE_IP:
                if not is_valid_ipv4(val):
                    m = RE_IP_DEFANGED.search(raw_val)
                    if not m or not is_valid_ipv4(m.group(0)):
                        continue
                    val = fang(m.group(0))
            elif ioc_type == TYPE_DOMAIN:
                m = RE_DOMAIN.search(raw_val)
                if not m:
                    continue
                val = fang(m.group(0))
                if endswith_forbidden_web_ext(val):
                    continue
            elif ioc_type == TYPE_EMAIL:
                m = RE_EMAIL.search(raw_val)
                if not m:
                    continue
                val = m.group(0).lower()
            elif ioc_type == TYPE_FILENAME:
                m = RE_FILENAME.search(raw_val)
                if not m:
                    continue
                val = m.group(0).lower()
                if endswith_forbidden_web_ext(val):
                    continue
            elif ioc_type in (TYPE_MD5, TYPE_SHA1, TYPE_SHA256):
                m = {TYPE_MD5: RE_MD5, TYPE_SHA1: RE_SHA1, TYPE_SHA256: RE_SHA256}[ioc_type].search(raw_val)
                if not m:
                    continue
                val = m.group(0).lower()

            # Canonicalize
            val = normalize_value(ioc_type, val)
            # Validate filters again
            if ioc_type == TYPE_IP and not is_valid_ipv4(val):
                continue
            if ioc_type == TYPE_DOMAIN and endswith_forbidden_web_ext(val):
                continue
            if ioc_type == TYPE_FILENAME and endswith_forbidden_web_ext(val):
                continue

            # Build row with arbitrary extra columns
            row = {"Type": ioc_type, "Value": val}
            # Add all other columns from the table row
            for k, v in norm.items():
                if k in ("Type", value_col):
                    continue
                if not v:
                    continue
                row[k] = v.strip()

            # Merge into index
            key = (ioc_type, val)
            if key in index:
                existing = index[key]
                # Prefer non-empty fields; keep the richest row
                changed = False
                for k, v in row.items():
                    if k in ("Type", "Value"):
                        continue
                    if v and not existing.get(k):
                        existing[k] = v
                        changed = True
                if changed:
                    new_or_updated += 1
            else:
                index[key] = row
                existing_rows.append(row)
                new_or_updated += 1

            # Expand header union
            header_candidates = ["Type", "Value"] + [k for k in row.keys() if k not in ("Type", "Value")]
            header = union_headers(header, header_candidates)
            parsed_any = True

        # If no pipe-table parsed, fall back to line-based parsing
        if not parsed_any:
            loose_rows = parse_loose_lines(sec)
            for row in loose_rows:
                t, v = row["Type"], normalize_value(row["Type"], row["Value"])
                if t == TYPE_IP and not is_valid_ipv4(v):
                    continue
                if t == TYPE_DOMAIN and endswith_forbidden_web_ext(v):
                    continue
                if t == TYPE_FILENAME and endswith_forbidden_web_ext(v):
                    continue
                key = (t, v)
                if key not in index:
                    index[key] = {"Type": t, "Value": v}
                    existing_rows.append(index[key])
                    new_or_updated += 1
                # header remains ["Type","Value"] for loose lines

    # Compose final header (always ensure mandatory first)
    # Keep mandatory first, then others in encountered order
    final_header = []
    for m in MANDATORY_OUTPUT:
        if m in header:
            final_header.append(m)
    for h in header:
        if h not in final_header:
            final_header.append(h)

    # Sort rows for stability by (Type, Value) case-insensitive
    existing_rows_sorted = sorted(existing_rows, key=lambda r: (r.get("Type","").lower(), r.get("Value","").lower()))

    # Write CSV
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=final_header, extrasaction="ignore")
        writer.writeheader()
        for r in existing_rows_sorted:
            writer.writerow(r)

    print(f"IOCs updated. Rows written: {len(existing_rows_sorted)}  |  New/updated this run: {new_or_updated}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
