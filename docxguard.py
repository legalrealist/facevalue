"""
docxguard.py -- Detect parser differential attacks in DOCX files.

Checks embedded font cmap manipulation (noroboto with OOXML de-obfuscation),
hidden text, revision marks, field codes, and AlternateContent blocks.
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

WML = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
MC = "http://schemas.openxmlformats.org/markup-compatibility/2006"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"


def _deobfuscate_font(font_bytes, font_guid):
    try:
        key = uuid.UUID(font_guid).bytes[::-1]
    except ValueError:
        return font_bytes
    data = bytearray(font_bytes)
    for i in range(min(32, len(data))):
        data[i] ^= key[i % 16]
    return bytes(data)


def _find_embedded_fonts(z):
    fonts = []
    try:
        root = etree.fromstring(z.read("word/fontTable.xml"))
    except KeyError:
        return fonts

    rels = {}
    try:
        for rel in etree.fromstring(z.read("word/_rels/fontTable.xml.rels")).findall(f"{{{PKG}}}Relationship"):
            rid = rel.get("Id", "")
            target = rel.get("Target", "")
            rels[rid] = f"word/{target}" if not target.startswith("/") else target.lstrip("/")
    except KeyError:
        pass

    for font_elem in root.findall(f"{{{WML}}}font"):
        name = font_elem.get(f"{{{WML}}}name", "")
        for style in ("embedRegular", "embedBold", "embedItalic", "embedBoldItalic"):
            embed = font_elem.find(f"{{{WML}}}{style}")
            if embed is None:
                continue
            rid = embed.get(f"{{{REL}}}id", "")
            guid = embed.get(f"{{{WML}}}fontKey", "").strip("{}")
            path = rels.get(rid, "")
            if path:
                fonts.append({"name": name, "path": path, "guid": guid})
    return fonts


def _check_embedded_font_cmap(z, font_info):
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

    cmap = tt.getBestCmap()
    if cmap is None:
        tt.close()
        return findings

    pua_count = 0
    for codepoint, glyph_name in cmap.items():
        if 0xE000 <= codepoint <= 0xF8FF or 0xF0000 <= codepoint <= 0xFFFFD:
            pua_count += 1
        elif (0x41 <= codepoint <= 0x5A or 0x61 <= codepoint <= 0x7A):
            expected = chr(codepoint)
            if len(glyph_name) == 1 and glyph_name.isalpha() and glyph_name != expected:
                findings.append({
                    "type": "font_cmap_mismatch", "font": font_name, "severity": "critical",
                    "message": f"Embedded font '{font_name}' glyph '{glyph_name}' mapped to U+{codepoint:04X} ('{expected}')",
                })

    if pua_count > 2:
        findings.append({
            "type": "font_cmap_pua", "font": font_name, "severity": "critical",
            "message": f"Embedded font '{font_name}' maps {pua_count} codepoints from Private Use Area",
        })

    tt.close()
    return findings


def _check_hidden_text(z):
    try:
        root = etree.fromstring(z.read("word/document.xml"))
    except KeyError:
        return []

    hidden_runs = []
    for run in root.iter(f"{{{WML}}}r"):
        rpr = run.find(f"{{{WML}}}rPr")
        if rpr is None:
            continue
        vanish = rpr.find(f"{{{WML}}}vanish")
        if vanish is None:
            continue
        if vanish.get(f"{{{WML}}}val", "true") in ("false", "0"):
            continue
        texts = [t.text for t in run.iter(f"{{{WML}}}t") if t.text]
        if texts:
            hidden_runs.append("".join(texts))

    if hidden_runs:
        total = sum(len(t) for t in hidden_runs)
        return [{"type": "hidden_text", "severity": "warning",
                 "message": f"{len(hidden_runs)} hidden text run(s) ({total} chars) — extractors read this but humans don't see it. Sample: '{hidden_runs[0][:80]}'"}]
    return []


def _check_revision_marks(z):
    try:
        root = etree.fromstring(z.read("word/document.xml"))
    except KeyError:
        return []

    findings = []
    deleted = [dt.text for dt in root.iter(f"{{{WML}}}delText") if dt.text]
    inserted = [t.text for ins in root.iter(f"{{{WML}}}ins") for t in ins.iter(f"{{{WML}}}t") if t.text]

    if deleted:
        total = sum(len(t) for t in deleted)
        findings.append({"type": "revision_deleted", "severity": "warning",
                         "message": f"{len(deleted)} deleted text segment(s) ({total} chars) still in XML. Sample: '{deleted[0][:80]}'"})
    if inserted and deleted:
        findings.append({"type": "revision_mixed", "severity": "warning",
                         "message": f"Unresolved track changes ({len(inserted)} insertions, {len(deleted)} deletions)"})
    return findings


def _check_field_codes(z):
    try:
        root = etree.fromstring(z.read("word/document.xml"))
    except KeyError:
        return []

    dde = sum(1 for i in root.iter(f"{{{WML}}}instrText")
              if i.text and i.text.strip().upper().startswith(("DDE", "DDEAUTO")))
    if dde:
        return [{"type": "field_dde", "severity": "critical",
                 "message": f"{dde} DDE field code(s) — execute external commands with misleading cached text"}]
    return []


def _check_alternate_content(z):
    try:
        root = etree.fromstring(z.read("word/document.xml"))
    except KeyError:
        return []

    count = sum(1 for _ in root.iter(f"{{{MC}}}AlternateContent"))
    if count:
        return [{"type": "alternate_content", "severity": "warning",
                 "message": f"{count} AlternateContent block(s) — different content for different consumers"}]
    return []


def scan_docx(docx_path):
    try:
        z = zipfile.ZipFile(docx_path)
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return {"file": os.path.basename(docx_path), "error": str(e),
                "summary": {"total_findings": 0, "critical": 0, "warning": 0}, "findings": []}

    findings = []
    for font_info in _find_embedded_fonts(z):
        findings.extend(_check_embedded_font_cmap(z, font_info))
    findings.extend(_check_hidden_text(z))
    findings.extend(_check_revision_marks(z))
    findings.extend(_check_field_codes(z))
    findings.extend(_check_alternate_content(z))
    z.close()

    findings = [f for f in findings if f["severity"] in ("critical", "warning")]
    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]
    return {
        "file": os.path.basename(docx_path),
        "summary": {"total_findings": len(findings), "critical": len(critical), "warning": len(warnings)},
        "findings": findings,
    }
