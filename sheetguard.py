"""
sheetguard.py -- Detect parser differential attacks in XLSX, PDF, and DOCX.

Scans at the raw structural level, bypassing the extraction libraries
that are themselves vulnerable to deception.
"""

import json
import os
import re
import sys
import zipfile
from lxml import etree

SPREADSHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _load_shared_strings(z):
    try:
        xml = z.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    return ["".join(t.text or "" for t in si.iter(f"{{{SPREADSHEET_NS}}}t"))
            for si in etree.fromstring(xml).findall(f"{{{SPREADSHEET_NS}}}si")]


def _load_styles(z):
    root = etree.fromstring(z.read("xl/styles.xml"))
    num_fmts = {0: "General", 1: "0", 2: "0.00", 3: "#,##0", 4: "#,##0.00",
                9: "0%", 10: "0.00%", 14: "mm-dd-yy"}

    fmt_elem = root.find(f"{{{SPREADSHEET_NS}}}numFmts")
    if fmt_elem is not None:
        for nf in fmt_elem.findall(f"{{{SPREADSHEET_NS}}}numFmt"):
            num_fmts[int(nf.get("numFmtId", 0))] = nf.get("formatCode", "")

    style_to_fmt = {}
    cell_xfs = root.find(f"{{{SPREADSHEET_NS}}}cellXfs")
    if cell_xfs is not None:
        for i, xf in enumerate(cell_xfs.findall(f"{{{SPREADSHEET_NS}}}xf")):
            style_to_fmt[i] = int(xf.get("numFmtId", 0))
    return num_fmts, style_to_fmt


def _is_static_format(format_code):
    if not format_code:
        return False, None
    cleaned = format_code.strip()
    if re.match(r'^"[^"]*"$', cleaned):
        return True, cleaned.strip('"')

    static_values = []
    for section in cleaned.split(";"):
        section_clean = re.sub(r'\[[^\]]*\]', '', section).strip()
        if re.match(r'^"[^"]*"$', section_clean):
            static_values.append(section_clean.strip('"'))
        elif section_clean in ("General", "0", "0.00", "#,##0", "#,##0.00",
                               "0%", "0.00%", "0.0%", "$#,##0", "$#,##0.00"):
            return False, None
        elif re.search(r'[0#.,]', section_clean) and '"' not in section_clean:
            return False, None

    return (True, static_values[0]) if static_values else (False, None)


def scan_workbook(xlsx_path):
    findings = []
    with zipfile.ZipFile(xlsx_path) as z:
        shared_strings = _load_shared_strings(z)
        num_fmts, style_to_fmt = _load_styles(z)

        for sheet_file in (n for n in z.namelist()
                           if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")):
            sheet_name = os.path.splitext(os.path.basename(sheet_file))[0]
            root = etree.fromstring(z.read(sheet_file))

            for cell in root.iter(f"{{{SPREADSHEET_NS}}}c"):
                if cell.get("t", "") == "s":
                    continue
                v_elem = cell.find(f"{{{SPREADSHEET_NS}}}v")
                if v_elem is None or v_elem.text is None:
                    continue
                try:
                    raw_value = float(v_elem.text)
                except ValueError:
                    continue

                fmt_id = style_to_fmt.get(int(cell.get("s", 0)), 0)
                format_code = num_fmts.get(fmt_id, "General")
                is_static, static_display = _is_static_format(format_code)
                if not is_static:
                    continue

                try:
                    display_numeric = float(
                        static_display.replace("$", "").replace(",", "")
                        .replace("%", "").replace("x", "").strip())
                    if "%" in static_display and abs(display_numeric) < 100:
                        display_numeric /= 100
                    if abs(raw_value) > 0.001 and abs(display_numeric) > 0.001:
                        if abs(display_numeric / raw_value - 1.0) < 0.01:
                            continue
                    elif abs(display_numeric - raw_value) < 0.01:
                        continue
                    severity = "critical"
                    message = f"Static format divergence: displays '{static_display}' but raw value is {raw_value}"
                except ValueError:
                    severity = "warning"
                    message = f"Static text format on numeric cell: displays '{static_display}', raw value is {raw_value}"

                findings.append({
                    "sheet": sheet_name, "cell": cell.get("r", "?"),
                    "severity": severity, "message": message,
                    "raw_value": raw_value, "format_code": format_code,
                    "static_display": static_display,
                })

    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]
    return {
        "file": os.path.basename(xlsx_path),
        "summary": {"total_findings": len(findings), "critical": len(critical), "warning": len(warnings)},
        "findings": findings,
    }


def scan_path(target_path):
    xlsx, pdf, docx = [], [], []
    if os.path.isfile(target_path):
        ext = target_path.lower()
        if ext.endswith(".xlsx"):
            xlsx = [scan_workbook(target_path)]
        elif ext.endswith(".pdf"):
            from pdfguard import scan_pdf
            pdf = [scan_pdf(target_path)]
        elif ext.endswith(".docx"):
            from docxguard import scan_docx
            docx = [scan_docx(target_path)]
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in sorted(files):
                if f.startswith("~$") or f.startswith("."):
                    continue
                full = os.path.join(root, f)
                lo = f.lower()
                if lo.endswith(".xlsx"):
                    xlsx.append(scan_workbook(full))
                elif lo.endswith(".pdf"):
                    from pdfguard import scan_pdf
                    pdf.append(scan_pdf(full))
                elif lo.endswith(".docx"):
                    from docxguard import scan_docx
                    docx.append(scan_docx(full))
    return xlsx, pdf, docx


def _format_findings(reports, file_type, stop_msg):
    if not reports:
        return None

    errors = [r for r in reports if r.get("error")]
    clean = [r for r in reports if not r.get("error")]
    lines = [f"[ERROR] {r['file']}: {r['error']}" for r in errors]
    if lines and clean:
        lines.append("")

    all_critical = sum(r["summary"]["critical"] for r in clean)
    all_warnings = sum(r["summary"]["warning"] for r in clean)

    if all_critical > 0:
        lines.append(f"[DIVERGENCE_DETECTED] {all_critical} finding(s) across {len(clean)} {file_type} file(s).")
        lines.extend(["", f"STOP. {stop_msg}", ""])
        for r in clean:
            if r["summary"]["critical"] == 0 and r["summary"]["warning"] == 0:
                continue
            lines.append(f"  File: {r['file']}")
            for f in r["findings"]:
                marker = "CRITICAL" if f["severity"] == "critical" else "WARNING"
                loc = f"  {f['sheet']}!{f['cell']}:" if "sheet" in f else f"  Page {f.get('page', '?')}:" if "page" in f else ""
                lines.append(f"    [{marker}]{loc} {f['message']}")
            lines.append("")
    elif all_warnings > 0:
        lines.append(f"[WARNING] {all_warnings} suspicious element(s) in {len(clean)} {file_type} file(s).")
        lines.append("")
        for r in clean:
            if r["summary"]["warning"] == 0:
                continue
            lines.append(f"  File: {r['file']}")
            for f in r["findings"]:
                lines.append(f"    [WARNING] {f['message']}")
            lines.append("")
    else:
        names = ", ".join(r["file"] for r in clean)
        lines.append(f"[SAFE] No divergence detected in: {names}")

    return "\n".join(lines) if lines else None


def format_report(xlsx, pdf=None, docx=None):
    parts = []

    out = _format_findings(xlsx, "XLSX",
        "Do not trust numeric values extracted from the flagged file(s). "
        "The displayed values and extracted values differ.")
    if out:
        parts.append(out)

    out = _format_findings(pdf, "PDF",
        "Do not trust text extracted from the flagged file(s). "
        "Font-level manipulation may cause displayed content to differ from extracted content.")
    if out:
        parts.append(out)

    out = _format_findings(docx, "DOCX",
        "Do not trust text extracted from the flagged file(s). "
        "Document structure or embedded fonts may cause displayed content to differ from extracted content.")
    if out:
        parts.append(out)

    return "\n\n".join(parts) if parts else "[SAFE] No document files found to scan."


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 sheetguard.py <file.xlsx|.pdf|.docx|directory> [...]", file=sys.stderr)
        sys.exit(1)

    all_xlsx, all_pdf, all_docx = [], [], []
    for path in sys.argv[1:]:
        if path.startswith("--"):
            continue
        xlsx, pdf, docx = scan_path(path)
        all_xlsx.extend(xlsx)
        all_pdf.extend(pdf)
        all_docx.extend(docx)

    if "--json" in sys.argv:
        print(json.dumps({"xlsx": all_xlsx, "pdf": all_pdf, "docx": all_docx}, indent=2))
    else:
        print(format_report(all_xlsx, all_pdf, all_docx))


if __name__ == "__main__":
    main()
