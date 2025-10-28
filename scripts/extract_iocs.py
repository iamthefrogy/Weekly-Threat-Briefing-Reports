#!/usr/bin/env python3
"""
Extract IOCs only from Section "4. Indicators of Compromise (IOCs)" in report .md files,
and update IOCs.csv with:
  - Minimum columns: Type, Value
  - A new column: Report (the report file(s) the IOC came from)
  - Plus any extra columns present in the section's table (union across all reports)

Features:
  - Canonicalize values: defanged [.] -> ., (at) -> @, lowercasing where appropriate
  - Validate IPv4; drop invalid addresses
  - Ignore web-asset suffixes for domains/filenames: .html, .htm, .php, .jsp, .asp, .aspx, .js, .css
  - Deduplicate by (Type,Value) after canonicalization
  - Merge rows for the same (Type,Value): keep the most complete set of extra columns
  - If the same IOC appears in multiple reports, aggregate their filenames in the "Report" column.
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

MANDATORY_OUTPUT = ["Type", "Value", "Report"]

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
        if "|" in lines[i].strip().lstrip("|"):
            header_line = lines[i].strip()
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines) and re.search(r"\|\s*:?-{3,}", lines[j]):
                headers = [h.strip() for h in header_line.strip("|").split("|")]
                j += 1
                while j < len(lines) and "|" in lines[j]:
                    row_vals = [c.strip() for c in lines[j].strip().strip("|").split("|")]
                    if len(row_vals) < len(headers):
                        row_vals += [""] * (len(headers) - len(row_vals))
                    elif len(row_vals) > len(headers):
                        row_vals = row_vals[:len(headers)]
                    rows.append(dict(zip(headers, row_vals)))
                    j += 1
                i = j
                continue
        i += 1
    return rows

# ---------- Fallback loose-line parsing inside Section 4 ----------
def parse_loose_lines(block: str) -> List[Dict[str, str]]:
    """
    Handle simpler bullet/line formats inside the section, e.g.:
      Domain `example[.]com` ...
      SHA256 `abc...` ...
    We reliably capture at least Type, Value.
    """
    rows: List[Dict[str, str]] = []
    for raw in block.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^(Domain|Domain Name|IP|SHA256|SHA1|MD5|Email|Email Address|Filename)\s+`?([^`\s]+)`?", line, re.IGNORECASE)
        if not m:
            continue
        type_token = m.group(1).lower()
        value_token = m.group(2).strip()

        if type_token in ("domain", "domain name"):
            ioc_type = TYPE_DOMAIN
            m_dom = RE_DOMAIN.search(value_token) or RE_DOMAIN.search(" " + value_token)
            if not m_dom:
                continue
            val = fang(m_dom.group(0))
            if endswith_forbidden_web_ext(val):
                continue
        elif type_token == "ip":
            ioc_type = TYPE_IP
            if not is_valid_ipv4(value_token):
                m_ip = RE_IP_DEFANGED.search(value_token)
                if not m_ip or not is_valid_ipv4(m_ip.group(0)):
                    continue
                val = fang(m_ip.group(0))
            else:
                val = value_token
        elif type_token == "sha256":
            ioc_type = TYPE_SHA256
            m_hash = RE_SHA256.search(value_token)
            if not m_hash:
                continue
            val = m_hash.group(0).lower()
        elif type_token == "sha1":
            ioc_type = TYPE_SHA1
            m_hash = RE_SHA1.search(value_token)
            if not m_hash:
                continue
            val = m_hash.group(0).lower()
        elif type_token == "md5":
            ioc_type = TYPE_MD5
            m_hash = RE_MD5.search(value_token)
            if not m_hash:
                continue
            val = m_hash.group(0).lower()
        elif type_token in ("email", "email address"):
            ioc_type = TYPE_EMAIL
            m_em = RE_EMAIL.search(value_token)
            if not m_em:
                continue
            val = m_em.group(0).lower()
        elif type_token == "filename":
            ioc_type = TYPE_FILENAME
            m_fn = RE_FILENAME.search(value_token)
            if not m_fn:
                continue
            val = m_fn.group(0).lower()
            if endswith_forbidden_web_ext(val):
                continue
        else:
            continue

        rows.append({"Type": ioc_type, "Value": normalize_value(ioc_type, val)})
    return rows

# ---------- CSV helpers ----------
def _split_reports(report_field: str) -> List[str]:
    """Split a semicolon-separated Report field into unique, trimmed parts."""
    parts = [p.strip() for p in (report_field or "").split(";") if p.strip()]
    # Dedup while preserving order
    seen = set()
    uniq = []
    for p in parts:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq

def _merge_report_field(existing: str, new_report: str) -> str:
    reports = _split_reports(existing) + [new_report]
    # Dedup + sort for stability
    reports = sorted(set(reports))
    return "; ".join(reports)

def load_existing_and_canonicalize(csv_path: Path) -> Tuple[List[Dict[str, str]], Dict[Tuple[str, str], Dict[str, str]]]:
    """
    Load existing CSV, canonicalize values, keep/merge Report column.
    Returns existing rows list and index map by (Type, Value).
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
            t = (row.get("Type") or "").strip()
            v = (row.get("Value") or "").strip()
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

            # Canonicalize row
            row_canon = dict(row)
            row_canon["Type"] = t
            row_canon["Value"] = v_norm
            # Keep Report (canonicalize by file name only; assume it's already plain)
            report_field = (row.get("Report") or "").strip()
            if report_field:
                row_canon["Report"] = "; ".join(sorted(set(_split_reports(report_field))))
            else:
                row_canon["Report"] = ""

            key = (t, v_norm)
            prev = index.get(key)
            if prev:
                # Merge: prefer non-empty fields; merge Report
                if row_canon.get("Report"):
                    prev["Report"] = _merge_report_field(prev.get("Report",""), row_canon["Report"])
                for k, v2 in row_canon.items():
                    if k in ("Type", "Value", "Report"):
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

# ---------- Files to process ----------
def iter_markdown_files(args: List[str]) -> Iterable[Path]:
    if args:
        for p in args:
            path = REPO_ROOT / p if not p.startswith("/") else Path(p)
            if path.suffix.lower() == ".md" and path.exists():
                yield path
        return
    for p in REPO_ROOT.rglob("*.md"):
        yield p

# ---------- Main ----------
def main(argv: List[str]) -> int:
    existing_rows, index = load_existing_and_canonicalize(CSV_PATH)
    # Start header with mandatory fields
    header: List[str] = MANDATORY_OUTPUT[:]
    for r in existing_rows:
        header = union_headers(header, [k for k in r.keys() if k not in header])

    md_files = list(iter_markdown_files(argv))
    new_or_updated = 0

    for md in md_files:
        report_name = md.name  # e.g., "21-Oct-2025.md"
        try:
            text = md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        sec = extract_section_4(text)
        if not sec:
            continue

        # ---- Prefer pipe tables for rich columns ----
        table_rows = parse_pipe_tables(sec)
        parsed_any = False

        for tr in table_rows:
            norm = { (k or "").strip(): (v or "").strip() for k, v in tr.items() }
            if "Type" not in norm:
                continue

            # Identify value column
            value_col = None
            for cand in ["Value", "Indicator", "IOC", "Indicator Value"]:
                if cand in norm and norm[cand]:
                    value_col = cand
                    break
            if not value_col:
                # Heuristic fallback: pick first non-Type non-empty column
                for k, v in norm.items():
                    if k.lower() == "type":
                        continue
                    if v:
                        value_col = k
                        break
            if not value_col:
                continue

            # Normalize type label
            ioc_type_raw = norm["Type"].strip().lower()
            if ioc_type_raw in ("domain", "domain name"):
                ioc_type = TYPE_DOMAIN
            elif ioc_type_raw == "ip":
                ioc_type = TYPE_IP
            elif ioc_type_raw == "sha256":
                ioc_type = TYPE_SHA256
            elif ioc_type_raw == "sha1":
                ioc_type = TYPE_SHA1
            elif ioc_type_raw == "md5":
                ioc_type = TYPE_MD5
            elif ioc_type_raw in ("email", "email address"):
                ioc_type = TYPE_EMAIL
            elif ioc_type_raw == "filename":
                ioc_type = TYPE_FILENAME
            else:
                continue

            raw_val = norm.get(value_col, "")
            if not raw_val:
                continue

            # Extract clean value from the cell
            val = raw_val.strip("` ").strip()
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

            val = normalize_value(ioc_type, val)
            # Filters again
            if ioc_type == TYPE_IP and not is_valid_ipv4(val):
                continue
            if ioc_type == TYPE_DOMAIN and endswith_forbidden_web_ext(val):
                continue
            if ioc_type == TYPE_FILENAME and endswith_forbidden_web_ext(val):
                continue

            row = {"Type": ioc_type, "Value": val, "Report": report_name}
            # carry extra columns from the table row
            for k, v in norm.items():
                if k in ("Type", value_col):
                    continue
                if v:
                    row[k] = v.strip()

            key = (ioc_type, val)
            if key in index:
                existing = index[key]
                # Merge: Reports aggregated; prefer richer fields
                existing["Report"] = _merge_report_field(existing.get("Report",""), report_name)
                changed = False
                for k, v in row.items():
                    if k in ("Type", "Value", "Report"):
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
            header = union_headers(header, [h for h in row.keys() if h not in header])
            parsed_any = True

        # ---- If no pipe tables parsed, fall back to loose line parsing ----
        if not parsed_any:
            loose_rows = parse_loose_lines(sec)
            for row in loose_rows:
                t, v = row["Type"], row["Value"]
                if t == TYPE_IP and not is_valid_ipv4(v):
                    continue
                if t == TYPE_DOMAIN and endswith_forbidden_web_ext(v):
                    continue
                if t == TYPE_FILENAME and endswith_forbidden_web_ext(v):
                    continue
                key = (t, v)
                if key in index:
                    # just add this report name to 'Report'
                    index[key]["Report"] = _merge_report_field(index[key].get("Report",""), report_name)
                else:
                    # only mandatory columns available in loose-line mode
                    new_row = {"Type": t, "Value": v, "Report": report_name}
                    index[key] = new_row
                    existing_rows.append(new_row)
                    new_or_updated += 1

    # Compose final header (ensure mandatory fields first)
    final_header = []
    for m in MANDATORY_OUTPUT:
        if m in header:
            final_header.append(m)
        else:
            final_header.append(m)  # ensure it's present even if never seen
    for h in header:
        if h not in final_header:
            final_header.append(h)

    # Sort rows by (Type, Value) for stability
    existing_rows_sorted = sorted(
        existing_rows,
        key=lambda r: (r.get("Type","").lower(), r.get("Value","").lower())
    )

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
