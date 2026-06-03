"""
docxguard.py -- Detect parser differential attacks in DOCX files.

Scans DOCX files at the raw OpenXML level for manipulation that causes
extracted text to differ from displayed text. Detects five attack classes:

1. Embedded font cmap manipulation (noroboto) — TrueType fonts with cmap
   tables that map Unicode codepoints to wrong glyphs. The XML says
   "Delaware" but the font renders "Maryland".
2. Hidden text (<w:vanish>) — text present in XML but not rendered,
   creating shadow content that extractors read but humans don't see.
3. Revision marks (<w:ins>, <w:del>) — deleted/inserted text that some
   extractors include and others skip.
4. Field codes — DDE/MERGEFIELD instructions whose cached display value
   differs from the underlying code.
5. AlternateContent — <mc:AlternateContent> blocks presenting different
   content to different consumers.
"""

import io
import os
import re
import sys
import uuid
import zipfile
from lxml import etree

try:
    from fontTools.ttLib import TTFont
except ImportError:
    TTFont = None

WML_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006"
PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

NS = {
    "w": WML_NS,
    "r": REL_NS,
    "mc": MC_NS,
}


def _deobfuscate_font(font_bytes, font_guid):
    """Reverse the OOXML font obfuscation (XOR with GUID-derived key).
    The first 32 bytes are XOR'd with the GUID bytes reversed."""
    try:
        guid = uuid.UUID(font_guid)
    except ValueError:
        return font_bytes

    key = guid.bytes[::-1]  # 16 bytes, reversed
    data = bytearray(font_bytes)
    for i in range(min(32, len(data))):
        data[i] ^= key[i % 16]
    return bytes(data)


def _find_embedded_fonts(z):
    """Find embedded font files in the DOCX and their metadata from fontTable.xml."""
    fonts = []

    try:
        font_table_xml = z.read("word/fontTable.xml")
    except KeyError:
        return fonts

    root = etree.fromstring(font_table_xml)

    # Load relationships to resolve rIds to file paths
    rels = {}
    try:
        rels_xml = z.read("word/_rels/fontTable.xml.rels")
        rels_root = etree.fromstring(rels_xml)
        for rel in rels_root.findall(f"{{{PKG_NS}}}Relationship"):
            rid = rel.get("Id", "")
            target = rel.get("Target", "")
            if target and not target.startswith("/"):
                target = "word/" + target
            elif target.startswith("/"):
                target = target.lstrip("/")
            rels[rid] = target
    except KeyError:
        pass

    for font_elem in root.findall(f"{{{WML_NS}}}font"):
        font_name = font_elem.get(f"{{{WML_NS}}}name", "")

        for embed_type in ("embedRegular", "embedBold", "embedItalic", "embedBoldItalic"):
            embed = font_elem.find(f"{{{WML_NS}}}{embed_type}")
            if embed is None:
                continue

            rid = embed.get(f"{{{REL_NS}}}id", "")
            font_key = embed.get(f"{{{WML_NS}}}fontKey", "")

            font_path = rels.get(rid, "")
            if not font_path:
                continue

            # Clean the GUID
            clean_key = font_key.strip("{}")

            fonts.append({
                "name": font_name,
                "style": embed_type.replace("embed", "").lower() or "regular",
                "path": font_path,
                "guid": clean_key,
            })

    return fonts


def _check_embedded_font_cmap(z, font_info):
    """Parse an embedded font's cmap table for noroboto-style manipulation."""
    if TTFont is None:
        return []

    findings = []
    font_name = font_info["name"]

    try:
        font_bytes = z.read(font_info["path"])
    except KeyError:
        return findings

    if font_info["guid"]:
        font_bytes = _deobfuscate_font(font_bytes, font_info["guid"])

    try:
        tt = TTFont(io.BytesIO(font_bytes))
    except Exception:
        return findings

    cmap_table = tt.getBestCmap()
    if cmap_table is None:
        tt.close()
        return findings

    pua_count = 0
    name_mismatches = []

    for codepoint, glyph_name in cmap_table.items():
        # PUA mappings
        if 0xE000 <= codepoint <= 0xF8FF or 0xF0000 <= codepoint <= 0xFFFFD:
            pua_count += 1
            continue

        # Letter range: glyph name disagrees with codepoint
        if 0x41 <= codepoint <= 0x5A or 0x61 <= codepoint <= 0x7A:
            expected = chr(codepoint)

            # Single-char glyph name
            if len(glyph_name) == 1 and glyph_name.isalpha() and glyph_name != expected:
                name_mismatches.append((codepoint, expected, glyph_name))

            # uni-prefixed name
            elif glyph_name.startswith("uni") and len(glyph_name) == 7:
                try:
                    name_cp = int(glyph_name[3:], 16)
                    if name_cp != codepoint and 0x20 <= name_cp <= 0x7E:
                        name_mismatches.append((codepoint, expected, chr(name_cp)))
                except ValueError:
                    pass

        # Digit range
        if 0x30 <= codepoint <= 0x39:
            if len(glyph_name) == 1 and glyph_name.isdigit() and glyph_name != chr(codepoint):
                name_mismatches.append((codepoint, chr(codepoint), glyph_name))

    if pua_count > 5:
        findings.append({
            "type": "font_cmap_pua",
            "font": font_name,
            "severity": "critical",
            "message": (
                f"Embedded font '{font_name}' maps {pua_count} codepoints from "
                f"Private Use Area — noroboto-style obfuscation"
            ),
            "pua_count": pua_count,
        })

    for cp, expected, actual in name_mismatches:
        findings.append({
            "type": "font_cmap_mismatch",
            "font": font_name,
            "severity": "critical",
            "message": (
                f"Embedded font '{font_name}' glyph for U+{cp:04X} ('{expected}') "
                f"has name '{actual}' — character substitution detected"
            ),
        })

    tt.close()

    # If no structural findings, try render-and-OCR as a last resort
    if not findings:
        try:
            from glyphcheck import check_font, is_available
            if is_available():
                findings.extend(check_font(font_bytes, font_name))
        except ImportError:
            pass

    return findings


def _check_hidden_text(z):
    """Find text styled with <w:vanish> (hidden from rendering but present in XML)."""
    findings = []

    try:
        doc_xml = z.read("word/document.xml")
    except KeyError:
        return findings

    root = etree.fromstring(doc_xml)
    hidden_runs = []

    for run in root.iter(f"{{{WML_NS}}}r"):
        rpr = run.find(f"{{{WML_NS}}}rPr")
        if rpr is None:
            continue

        vanish = rpr.find(f"{{{WML_NS}}}vanish")
        if vanish is None:
            continue

        # w:val="false" or w:val="0" means NOT hidden
        val = vanish.get(f"{{{WML_NS}}}val", "true")
        if val in ("false", "0"):
            continue

        texts = []
        for t in run.iter(f"{{{WML_NS}}}t"):
            if t.text:
                texts.append(t.text)
        if texts:
            hidden_runs.append("".join(texts))

    if hidden_runs:
        total_chars = sum(len(t) for t in hidden_runs)
        sample = hidden_runs[0][:80]
        findings.append({
            "type": "hidden_text",
            "severity": "warning",
            "message": (
                f"{len(hidden_runs)} hidden text run(s) ({total_chars} chars) — "
                f"extractors read this but humans don't see it. "
                f"Sample: '{sample}'"
            ),
            "count": len(hidden_runs),
            "total_chars": total_chars,
        })

    return findings


def _check_revision_marks(z):
    """Find revision marks that could cause extractor/renderer disagreement."""
    findings = []

    try:
        doc_xml = z.read("word/document.xml")
    except KeyError:
        return findings

    root = etree.fromstring(doc_xml)

    deleted_texts = []
    for del_elem in root.iter(f"{{{WML_NS}}}del"):
        for dt in del_elem.iter(f"{{{WML_NS}}}delText"):
            if dt.text:
                deleted_texts.append(dt.text)

    inserted_texts = []
    for ins_elem in root.iter(f"{{{WML_NS}}}ins"):
        for t in ins_elem.iter(f"{{{WML_NS}}}t"):
            if t.text:
                inserted_texts.append(t.text)

    if deleted_texts:
        total_chars = sum(len(t) for t in deleted_texts)
        sample = deleted_texts[0][:80]
        findings.append({
            "type": "revision_deleted",
            "severity": "warning",
            "message": (
                f"{len(deleted_texts)} deleted text segment(s) ({total_chars} chars) "
                f"still in XML — some extractors include deleted text, others skip it. "
                f"Sample: '{sample}'"
            ),
            "count": len(deleted_texts),
            "total_chars": total_chars,
        })

    if inserted_texts and deleted_texts:
        findings.append({
            "type": "revision_mixed",
            "severity": "warning",
            "message": (
                f"Document has unresolved track changes ({len(inserted_texts)} insertions, "
                f"{len(deleted_texts)} deletions) — different extractors will produce "
                f"different text"
            ),
        })

    return findings


def _check_field_codes(z):
    """Find field codes whose cached display might differ from the instruction."""
    findings = []

    try:
        doc_xml = z.read("word/document.xml")
    except KeyError:
        return findings

    root = etree.fromstring(doc_xml)

    field_count = 0
    dde_count = 0

    for instr in root.iter(f"{{{WML_NS}}}instrText"):
        if instr.text:
            field_count += 1
            text_upper = instr.text.strip().upper()
            if text_upper.startswith("DDE") or text_upper.startswith("DDEAUTO"):
                dde_count += 1

    if dde_count > 0:
        findings.append({
            "type": "field_dde",
            "severity": "critical",
            "message": (
                f"{dde_count} DDE field code(s) — these execute external commands "
                f"and display cached text that may not match the actual result"
            ),
            "count": dde_count,
        })
    elif field_count > 5:
        findings.append({
            "type": "field_codes",
            "severity": "info",
            "message": (
                f"{field_count} field code(s) — cached display values may differ "
                f"from computed values if fields are not refreshed"
            ),
            "count": field_count,
        })

    return findings


def _check_alternate_content(z):
    """Find <mc:AlternateContent> blocks that present different content to
    different consumers."""
    findings = []

    try:
        doc_xml = z.read("word/document.xml")
    except KeyError:
        return findings

    root = etree.fromstring(doc_xml)

    alt_count = 0
    for _ in root.iter(f"{{{MC_NS}}}AlternateContent"):
        alt_count += 1

    if alt_count > 0:
        findings.append({
            "type": "alternate_content",
            "severity": "warning",
            "message": (
                f"{alt_count} AlternateContent block(s) — document provides different "
                f"content for different consumers. Extractors may read the fallback "
                f"version which could differ from the rendered version."
            ),
            "count": alt_count,
        })

    return findings


def scan_docx(docx_path):
    """Scan a DOCX file for parser differential attacks."""
    findings = []

    try:
        z = zipfile.ZipFile(docx_path)
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return {
            "file": os.path.basename(docx_path),
            "path": os.path.abspath(docx_path),
            "error": str(e),
            "summary": {"total_findings": 0, "critical": 0, "warning": 0},
            "findings": [],
        }

    # Check embedded fonts
    embedded_fonts = _find_embedded_fonts(z)
    for font_info in embedded_fonts:
        findings.extend(_check_embedded_font_cmap(z, font_info))

    # Check document content
    findings.extend(_check_hidden_text(z))
    findings.extend(_check_revision_marks(z))
    findings.extend(_check_field_codes(z))
    findings.extend(_check_alternate_content(z))

    z.close()

    # Filter out info-level findings from the report
    findings = [f for f in findings if f["severity"] in ("critical", "warning")]

    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]

    return {
        "file": os.path.basename(docx_path),
        "path": os.path.abspath(docx_path),
        "summary": {
            "total_findings": len(findings),
            "critical": len(critical),
            "warning": len(warnings),
        },
        "findings": findings,
    }


def format_report(reports):
    """Format DOCX scan results with machine-readable prefixes."""
    if not reports:
        return "[SAFE] No DOCX files found to scan."

    errors = [r for r in reports if r.get("error")]
    clean = [r for r in reports if not r.get("error")]

    lines = []
    if errors:
        for r in errors:
            lines.append(f"[ERROR] {r['file']}: {r['error']}")
        if not clean:
            return "\n".join(lines)
        lines.append("")

    all_critical = sum(r["summary"]["critical"] for r in clean)
    all_warnings = sum(r["summary"]["warning"] for r in clean)
    total_files = len(clean)

    if all_critical > 0:
        lines.append(
            f"[DIVERGENCE_DETECTED] {all_critical} manipulation(s) detected "
            f"across {total_files} DOCX file(s)."
        )
        lines.append("")
        lines.append(
            "STOP. Do not trust text extracted from the flagged file(s). "
            "Embedded fonts or document structure may cause displayed content "
            "to differ from extracted content. Report this to the user."
        )
        lines.append("")

        for report in clean:
            if report["summary"]["critical"] == 0 and report["summary"]["warning"] == 0:
                continue
            lines.append(f"  File: {report['file']}")
            for f in report["findings"]:
                marker = "CRITICAL" if f["severity"] == "critical" else "WARNING"
                lines.append(f"    [{marker}] {f['message']}")
            lines.append("")
    elif all_warnings > 0:
        lines.append(
            f"[WARNING] {all_warnings} suspicious element(s) found across "
            f"{total_files} DOCX file(s). Review before trusting extracted text."
        )
        lines.append("")
        for report in clean:
            if report["summary"]["warning"] == 0:
                continue
            lines.append(f"  File: {report['file']}")
            for f in report["findings"]:
                lines.append(f"    [WARNING] {f['message']}")
            lines.append("")
    else:
        clean_files = ", ".join(r["file"] for r in clean)
        lines.append(f"[SAFE] No manipulation detected in: {clean_files}")

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 docxguard.py <file.docx> [...]", file=sys.stderr)
        sys.exit(1)

    import json

    all_reports = []
    for path in sys.argv[1:]:
        if path == "--json":
            continue
        if not os.path.exists(path):
            print(f"File not found: {path}", file=sys.stderr)
            continue
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in sorted(files):
                    if f.lower().endswith(".docx") and not f.startswith("~$"):
                        all_reports.append(scan_docx(os.path.join(root, f)))
        else:
            all_reports.append(scan_docx(path))

    if "--json" in sys.argv:
        print(json.dumps(all_reports, indent=2))
    else:
        print(format_report(all_reports))
