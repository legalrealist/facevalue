"""
facevalue.py — Don't take documents at face value.

Every extraction library trusts that the value it reads from a document
is the value the document displays. This assumption is wrong. XLSX
number formats can hardcode a display string decoupled from the raw
value. PDF fonts can remap characters via /ToUnicode or swap glyph
outlines. DOCX can hide text or embed lying fonts behind an XOR
obfuscation layer. None of the extraction libraries check for this.

This scanner works at the raw structural level — the same XML, the same
font tables — so it isn't vulnerable to the same tricks it detects.
"""

import json
import os
import re
import sys
import zipfile
from lxml import etree

NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

BUILTIN_FMTS = {0: "General", 1: "0", 2: "0.00", 3: "#,##0", 4: "#,##0.00",
                9: "0%", 10: "0.00%", 14: "mm-dd-yy"}

DYNAMIC_FORMAT_CHARS = {"General", "0", "0.00", "#,##0", "#,##0.00",
                        "0%", "0.00%", "0.0%", "$#,##0", "$#,##0.00"}


def _load_styles(z):
    root = etree.fromstring(z.read("xl/styles.xml"))
    num_fmts = dict(BUILTIN_FMTS)

    fmt_elem = root.find(f"{{{NS}}}numFmts")
    if fmt_elem is not None:
        for nf in fmt_elem.findall(f"{{{NS}}}numFmt"):
            num_fmts[int(nf.get("numFmtId", 0))] = nf.get("formatCode", "")

    style_to_fmt = {}
    cell_xfs = root.find(f"{{{NS}}}cellXfs")
    if cell_xfs is not None:
        for i, xf in enumerate(cell_xfs.findall(f"{{{NS}}}xf")):
            style_to_fmt[i] = int(xf.get("numFmtId", 0))
    return num_fmts, style_to_fmt


def _is_static_format(fmt):
    """A static format always displays the same string regardless of cell value.
    That's the hallmark of a poisoned cell — the format IS the lie."""
    if not fmt:
        return False, None
    cleaned = fmt.strip()
    if re.match(r'^"[^"]*"$', cleaned):
        return True, cleaned.strip('"')

    static_values = []
    for section in cleaned.split(";"):
        bare = re.sub(r'\[[^\]]*\]', '', section).strip()
        if re.match(r'^"[^"]*"$', bare):
            static_values.append(bare.strip('"'))
        elif bare in DYNAMIC_FORMAT_CHARS:
            return False, None
        elif re.search(r'[0#.,]', bare) and '"' not in bare:
            return False, None

    return (True, static_values[0]) if static_values else (False, None)


def _values_match(raw, display_str):
    """Check whether a static display string is consistent with the raw value.
    Returns True if they agree (not an attack), False if they diverge."""
    try:
        display = float(display_str.replace("$", "").replace(",", "")
                        .replace("%", "").replace("x", "").strip())
        if "%" in display_str and abs(display) < 100:
            display /= 100
        if abs(raw) > 0.001 and abs(display) > 0.001:
            return abs(display / raw - 1.0) < 0.01
        return abs(display - raw) < 0.01
    except ValueError:
        return None


def scan_workbook(path):
    findings = []
    with zipfile.ZipFile(path) as z:
        num_fmts, style_to_fmt = _load_styles(z)

        for sheet_file in (n for n in z.namelist()
                           if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")):
            sheet = os.path.splitext(os.path.basename(sheet_file))[0]
            root = etree.fromstring(z.read(sheet_file))

            for cell in root.iter(f"{{{NS}}}c"):
                if cell.get("t", "") == "s":
                    continue
                v = cell.find(f"{{{NS}}}v")
                if v is None or v.text is None:
                    continue
                try:
                    raw = float(v.text)
                except ValueError:
                    continue

                fmt_id = style_to_fmt.get(int(cell.get("s", 0)), 0)
                is_static, display = _is_static_format(num_fmts.get(fmt_id, "General"))
                if not is_static:
                    continue

                match = _values_match(raw, display)
                if match is True:
                    continue

                findings.append({
                    "sheet": sheet, "cell": cell.get("r", "?"),
                    "severity": "critical" if match is False else "warning",
                    "message": f"displays '{display}' but raw value is {raw}",
                    "raw_value": raw, "format_code": num_fmts.get(fmt_id),
                    "static_display": display,
                })

    critical = sum(1 for f in findings if f["severity"] == "critical")
    return {
        "file": os.path.basename(path),
        "summary": {"total_findings": len(findings), "critical": critical, "warning": len(findings) - critical},
        "findings": findings,
    }


# --- Dispatch and formatting ---

def scan_path(target):
    xlsx, pdf, docx = [], [], []
    if os.path.isfile(target):
        lo = target.lower()
        if lo.endswith(".xlsx"):   xlsx = [scan_workbook(target)]
        elif lo.endswith(".pdf"):  from pdfguard import scan_pdf; pdf = [scan_pdf(target)]
        elif lo.endswith(".docx"): from docxguard import scan_docx; docx = [scan_docx(target)]
    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            for f in sorted(files):
                if f.startswith(("~$", ".")):
                    continue
                full = os.path.join(root, f)
                lo = f.lower()
                if lo.endswith(".xlsx"):   xlsx.append(scan_workbook(full))
                elif lo.endswith(".pdf"):  from pdfguard import scan_pdf; pdf.append(scan_pdf(full))
                elif lo.endswith(".docx"): from docxguard import scan_docx; docx.append(scan_docx(full))
    return xlsx, pdf, docx


def _format_findings(reports, label, stop_msg):
    if not reports:
        return None
    errors = [r for r in reports if r.get("error")]
    clean = [r for r in reports if not r.get("error")]
    lines = [f"[ERROR] {r['file']}: {r['error']}" for r in errors]

    total_crit = sum(r["summary"]["critical"] for r in clean)
    total_warn = sum(r["summary"]["warning"] for r in clean)

    if total_crit > 0:
        lines.append(f"[DIVERGENCE_DETECTED] {total_crit} finding(s) across {len(clean)} {label} file(s).")
        lines.extend(["", f"STOP. {stop_msg}", ""])
        for r in clean:
            if not r["summary"]["total_findings"]:
                continue
            lines.append(f"  File: {r['file']}")
            for f in r["findings"]:
                tag = "CRITICAL" if f["severity"] == "critical" else "WARNING"
                loc = f" {f['sheet']}!{f['cell']}:" if "sheet" in f else f" p{f.get('page', '?')}:" if "page" in f else ""
                lines.append(f"    [{tag}]{loc} {f['message']}")
            lines.append("")
    elif total_warn > 0:
        lines.append(f"[WARNING] {total_warn} suspicious element(s) in {len(clean)} {label} file(s).")
        lines.append("")
        for r in clean:
            for f in r["findings"]:
                lines.append(f"    [WARNING] {f['message']}")
    elif clean:
        lines.append(f"[SAFE] No divergence in: {', '.join(r['file'] for r in clean)}")

    return "\n".join(lines) or None


STOP_XLSX = "Do not trust numeric values from the flagged file(s). Displayed values and extracted values differ."
STOP_PDF = "Do not trust text from the flagged file(s). Font-level manipulation may decouple display from extraction."
STOP_DOCX = "Do not trust text from the flagged file(s). Document structure or embedded fonts may decouple display from extraction."


def format_report(xlsx, pdf=None, docx=None):
    parts = [p for p in (
        _format_findings(xlsx, "XLSX", STOP_XLSX),
        _format_findings(pdf, "PDF", STOP_PDF),
        _format_findings(docx, "DOCX", STOP_DOCX),
    ) if p]
    return "\n\n".join(parts) if parts else "[SAFE] No document files found to scan."


def main():
    if len(sys.argv) < 2:
        print("Usage: facevalue.py <file|directory> [...]", file=sys.stderr)
        sys.exit(1)

    all_xlsx, all_pdf, all_docx = [], [], []
    for path in sys.argv[1:]:
        if path.startswith("--"):
            continue
        x, p, d = scan_path(path)
        all_xlsx += x; all_pdf += p; all_docx += d

    if "--json" in sys.argv:
        print(json.dumps({"xlsx": all_xlsx, "pdf": all_pdf, "docx": all_docx}, indent=2))
    else:
        print(format_report(all_xlsx, all_pdf, all_docx))


if __name__ == "__main__":
    main()
