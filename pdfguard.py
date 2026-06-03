"""
pdfguard.py — Parser differential detection for PDF.

PDF text extraction trusts two things: the /ToUnicode CMap (which maps
character codes to Unicode) and the embedded font's cmap table (which
maps codepoints to glyphs). Both can lie. A /ToUnicode can remap '1' to
'9'. An embedded font can map codepoints to Private Use Area garbage. An
/ActualText span can silently override what extraction reads. An /Encoding
/Differences array can slot standard glyphs into high-byte positions for
partial obfuscation. Every PDF text extractor trusts these structures.
"""

import io
import os
import re

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from fontTools.ttLib import TTFont
except ImportError:
    TTFont = None


def _parse_tounicode(cmap_bytes):
    text = cmap_bytes.decode("latin-1", errors="replace")
    mappings = []
    for m in re.finditer(r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>", text):
        try:
            src = int(m.group(1), 16)
            dst = bytes.fromhex(m.group(2)).decode("utf-16-be", errors="replace")
            mappings.append((src, dst))
        except (ValueError, UnicodeDecodeError):
            continue
    return mappings


def _check_tounicode(font_obj, name):
    tu = font_obj.get("/ToUnicode")
    if tu is None:
        return []
    try:
        mappings = _parse_tounicode(tu.read_bytes())
    except Exception:
        return []

    findings, pua = [], 0
    for src, dst in mappings:
        if not dst:
            continue
        d = ord(dst[0])
        if 0xE000 <= d <= 0xF8FF or 0xF0000 <= d <= 0xFFFFD:
            pua += 1
        elif 0x20 <= src <= 0x7E and 0x20 <= d <= 0x7E and src != d:
            s, t = chr(src), dst[0]
            if (s.isdigit() and t.isdigit()) or (s.isalpha() and t.isalpha()):
                findings.append({"severity": "critical", "font": name,
                    "message": f"Font '{name}' /ToUnicode remaps '{s}' → '{t}'"})
    if pua:
        findings.append({"severity": "critical", "font": name,
            "message": f"Font '{name}' /ToUnicode maps {pua} char(s) to Private Use Area"})
    return findings


def _get_font_bytes(font_obj):
    """Walk the font descriptor chain — direct for simple fonts, through
    /DescendantFonts for Type0/CID composites."""
    desc = font_obj.get("/FontDescriptor")
    if desc is None:
        df = font_obj.get("/DescendantFonts")
        if df:
            try: desc = df[0].get("/FontDescriptor")
            except Exception: pass
    if desc is None:
        return None
    for k in ("/FontFile2", "/FontFile3", "/FontFile"):
        ff = desc.get(k)
        if ff:
            try: return ff.read_bytes()
            except Exception: pass
    return None


def _check_embedded_font(font_obj, name):
    if TTFont is None:
        return []
    font_bytes = _get_font_bytes(font_obj)
    if not font_bytes:
        return []
    try:
        tt = TTFont(io.BytesIO(font_bytes))
    except Exception:
        return []

    findings = []

    # Known-malicious font families
    try:
        for rec in tt["name"].names:
            if rec.nameID in (1, 4, 6):
                try:
                    if "noroboto" in rec.toUnicode().lower():
                        findings.append({"severity": "critical", "font": name,
                            "message": f"Font '{name}' embeds known-malicious font '{rec.toUnicode()}'"})
                        break
                except Exception: pass
    except Exception: pass

    cmap = tt.getBestCmap()
    if cmap:
        pua = 0
        for cp, glyph in cmap.items():
            if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD:
                pua += 1
            elif (0x41 <= cp <= 0x5A or 0x61 <= cp <= 0x7A):
                if len(glyph) == 1 and glyph.isalpha() and glyph != chr(cp):
                    findings.append({"severity": "critical", "font": name,
                        "message": f"Font '{name}' glyph '{glyph}' mapped to U+{cp:04X} ('{chr(cp)}')"})
            elif 0x30 <= cp <= 0x39:
                if len(glyph) == 1 and glyph.isdigit() and glyph != chr(cp):
                    findings.append({"severity": "critical", "font": name,
                        "message": f"Font '{name}' glyph '{glyph}' mapped to digit '{chr(cp)}'"})
        if pua > 2:
            findings.append({"severity": "critical", "font": name,
                "message": f"Font '{name}' maps {pua} codepoints from Private Use Area"})

    tt.close()
    return findings


def _check_actualtext(page):
    try:
        c = page.get("/Contents")
        if c is None: return []
        raw = b"".join(s.read_bytes() for s in c) if isinstance(c, pikepdf.Array) else c.read_bytes()
    except Exception:
        return []

    findings = []
    for m in re.finditer(r'/ActualText\s*(?:\(([^)]*)\)|<([0-9a-fA-F]*)>)', raw.decode("latin-1", errors="replace"), re.DOTALL):
        lit, hx = m.group(1), m.group(2)
        txt = lit if lit is not None else (bytes.fromhex(hx).decode("utf-16-be", errors="replace") if hx else "")
        if txt.strip():
            findings.append({"severity": "warning",
                "message": f"/ActualText override: extraction reads '{txt[:80]}' regardless of display"})
    return findings


def _check_encoding(font_obj, name):
    enc = font_obj.get("/Encoding")
    if not enc or not isinstance(enc, pikepdf.Dictionary):
        return []
    diffs = enc.get("/Differences")
    if not diffs:
        return []
    try:
        items = list(diffs)
    except Exception:
        return []

    code, remaps, high = 0, [], []
    for item in items:
        if isinstance(item, (int, pikepdf.objects.Object)):
            try: code = int(item)
            except (ValueError, TypeError): pass
        elif isinstance(item, pikepdf.Name):
            g = str(item).lstrip("/")
            if 0x41 <= code <= 0x5A or 0x61 <= code <= 0x7A:
                if len(g) == 1 and g.isalpha() and g != chr(code):
                    remaps.append((chr(code), g))
            elif code >= 0x80 and len(g) == 1 and g.isalnum():
                high.append((code, g))
            code += 1

    findings = []
    if remaps:
        detail = ", ".join(f"'{a}'→'{b}'" for a, b in remaps[:5])
        findings.append({"severity": "critical", "font": name,
            "message": f"Font '{name}' /Encoding remaps {len(remaps)} char(s): {detail}"})
    if len(high) > 5:
        detail = ", ".join(f"0x{p:02X}→'{g}'" for p, g in high[:5])
        findings.append({"severity": "critical", "font": name,
            "message": f"Font '{name}' /Encoding maps {len(high)} high-byte positions to standard glyphs: {detail}"})
    return findings


def scan_pdf(path):
    if pikepdf is None:
        return {"file": os.path.basename(path), "error": "pikepdf not installed",
                "summary": {"total_findings": 0, "critical": 0, "warning": 0}, "findings": []}
    try:
        pdf = pikepdf.open(path)
    except Exception as e:
        return {"file": os.path.basename(path), "error": str(e),
                "summary": {"total_findings": 0, "critical": 0, "warning": 0}, "findings": []}

    findings, seen = [], set()
    for pg, page in enumerate(pdf.pages, 1):
        for f in _check_actualtext(page):
            f["page"] = pg; findings.append(f)

        fonts = (page.get("/Resources") or {}).get("/Font")
        if not fonts:
            continue
        for key in fonts.keys():
            name = str(key).lstrip("/")
            if name in seen: continue
            seen.add(name)
            for check in (_check_tounicode, _check_encoding, _check_embedded_font):
                for f in check(fonts[key], name):
                    f["page"] = pg; findings.append(f)

    pdf.close()
    crit = sum(1 for f in findings if f["severity"] == "critical")
    return {"file": os.path.basename(path),
            "summary": {"total_findings": len(findings), "critical": crit, "warning": len(findings) - crit},
            "findings": findings}
