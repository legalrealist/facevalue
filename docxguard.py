"""
docxguard.py — Parser differential detection for DOCX.

DOCX is a ZIP of XML parts. The text lives in <w:t> elements —
extraction tools read those and never look at the embedded fonts.
But Word renders using the embedded fonts, which can lie: the noroboto
attack embeds a TrueType font whose cmap maps codepoints to wrong
glyphs. The XML says "Delaware", the font draws "Maryland".

OOXML wraps embedded fonts in a lightweight XOR obfuscation (the font
GUID reversed as a 16-byte key over the first 32 bytes). We reverse
that to get at the raw TTF and check its cmap table.

Beyond fonts: hidden text (<w:vanish>) is in the XML but not rendered,
unresolved track changes create extractor disagreement, DDE field codes
execute external commands with misleading cached display values.
"""

import io
import os
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


def _deobfuscate(font_bytes, guid_str):
    """Reverse the OOXML font obfuscation — XOR first 32 bytes with
    the font's GUID reversed. Spec says this deters casual extraction.
    It doesn't deter us."""
    try:
        key = uuid.UUID(guid_str).bytes[::-1]
    except ValueError:
        return font_bytes
    data = bytearray(font_bytes)
    for i in range(min(32, len(data))):
        data[i] ^= key[i % 16]
    return bytes(data)


def _find_fonts(z):
    try:
        root = etree.fromstring(z.read("word/fontTable.xml"))
    except KeyError:
        return []

    rels = {}
    try:
        for r in etree.fromstring(z.read("word/_rels/fontTable.xml.rels")).findall(f"{{{PKG}}}Relationship"):
            rid, target = r.get("Id", ""), r.get("Target", "")
            rels[rid] = f"word/{target}" if not target.startswith("/") else target.lstrip("/")
    except KeyError:
        pass

    fonts = []
    for fe in root.findall(f"{{{WML}}}font"):
        name = fe.get(f"{{{WML}}}name", "")
        for style in ("embedRegular", "embedBold", "embedItalic", "embedBoldItalic"):
            embed = fe.find(f"{{{WML}}}{style}")
            if embed is None: continue
            path = rels.get(embed.get(f"{{{REL}}}id", ""), "")
            if path:
                fonts.append({"name": name, "path": path,
                              "guid": embed.get(f"{{{WML}}}fontKey", "").strip("{}")})
    return fonts


def _check_font_cmap(z, info):
    if TTFont is None:
        return []
    name = info["name"]
    try:
        raw = z.read(info["path"])
    except KeyError:
        return []

    font_bytes = _deobfuscate(raw, info["guid"]) if info["guid"] else raw
    try:
        tt = TTFont(io.BytesIO(font_bytes))
    except Exception:
        return []

    cmap = tt.getBestCmap()
    if not cmap:
        tt.close(); return []

    findings, pua = [], 0
    for cp, glyph in cmap.items():
        if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD:
            pua += 1
        elif (0x41 <= cp <= 0x5A or 0x61 <= cp <= 0x7A):
            if len(glyph) == 1 and glyph.isalpha() and glyph != chr(cp):
                findings.append({"severity": "critical", "font": name,
                    "message": f"Embedded font '{name}' glyph '{glyph}' mapped to U+{cp:04X} ('{chr(cp)}')"})
    if pua > 2:
        findings.append({"severity": "critical", "font": name,
            "message": f"Embedded font '{name}' maps {pua} codepoints from Private Use Area"})

    tt.close()
    return findings


def _check_doc_xml(z):
    """Parse document.xml once and check for hidden text, revisions,
    DDE field codes, and AlternateContent blocks."""
    try:
        root = etree.fromstring(z.read("word/document.xml"))
    except KeyError:
        return []

    findings = []

    # Hidden text — in the XML but styled invisible
    hidden = []
    for run in root.iter(f"{{{WML}}}r"):
        rpr = run.find(f"{{{WML}}}rPr")
        if rpr is None: continue
        v = rpr.find(f"{{{WML}}}vanish")
        if v is None or v.get(f"{{{WML}}}val", "true") in ("false", "0"):
            continue
        texts = [t.text for t in run.iter(f"{{{WML}}}t") if t.text]
        if texts:
            hidden.append("".join(texts))
    if hidden:
        total = sum(len(t) for t in hidden)
        findings.append({"severity": "warning",
            "message": f"{len(hidden)} hidden run(s) ({total} chars) — extractors read this, humans don't. Sample: '{hidden[0][:80]}'"})

    # Revision marks — deleted text lingers in XML
    deleted = [dt.text for dt in root.iter(f"{{{WML}}}delText") if dt.text]
    inserted = [t.text for ins in root.iter(f"{{{WML}}}ins") for t in ins.iter(f"{{{WML}}}t") if t.text]
    if deleted:
        findings.append({"severity": "warning",
            "message": f"{len(deleted)} deleted segment(s) ({sum(len(t) for t in deleted)} chars) still in XML. Sample: '{deleted[0][:80]}'"})
    if inserted and deleted:
        findings.append({"severity": "warning",
            "message": f"Unresolved track changes ({len(inserted)} insertions, {len(deleted)} deletions)"})

    # DDE field codes
    dde = sum(1 for i in root.iter(f"{{{WML}}}instrText")
              if i.text and i.text.strip().upper().startswith(("DDE", "DDEAUTO")))
    if dde:
        findings.append({"severity": "critical",
            "message": f"{dde} DDE field code(s) — external commands with misleading cached text"})

    # AlternateContent
    alt = sum(1 for _ in root.iter(f"{{{MC}}}AlternateContent"))
    if alt:
        findings.append({"severity": "warning",
            "message": f"{alt} AlternateContent block(s) — different content for different consumers"})

    return findings


def scan_docx(path):
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        return {"file": os.path.basename(path), "error": str(e),
                "summary": {"total_findings": 0, "critical": 0, "warning": 0}, "findings": []}

    findings = []
    for info in _find_fonts(z):
        findings.extend(_check_font_cmap(z, info))
    findings.extend(_check_doc_xml(z))
    z.close()

    findings = [f for f in findings if f["severity"] in ("critical", "warning")]
    crit = sum(1 for f in findings if f["severity"] == "critical")
    return {"file": os.path.basename(path),
            "summary": {"total_findings": len(findings), "critical": crit, "warning": len(findings) - crit},
            "findings": findings}
