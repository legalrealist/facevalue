"""
pdfguard.py -- Detect parser differential attacks in PDF files.

Checks /ToUnicode CMap remapping, embedded font cmap manipulation,
/ActualText overrides, and /Encoding /Differences remapping.
"""

import io
import os
import re
import sys

try:
    import pikepdf
except ImportError:
    pikepdf = None

try:
    from fontTools.ttLib import TTFont
except ImportError:
    TTFont = None

KNOWN_MALICIOUS_NAMES = ("noroboto",)


def _parse_tounicode_cmap(cmap_bytes):
    text = cmap_bytes.decode("latin-1", errors="replace")
    mappings = []
    for match in re.finditer(r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>", text):
        try:
            src = int(match.group(1), 16)
            dst_chars = bytes.fromhex(match.group(2)).decode("utf-16-be", errors="replace")
            mappings.append((src, dst_chars))
        except (ValueError, UnicodeDecodeError):
            continue
    return mappings


def _check_tounicode(font_obj, font_name):
    findings = []
    tounicode = font_obj.get("/ToUnicode")
    if tounicode is None:
        return findings
    try:
        cmap_bytes = tounicode.read_bytes()
    except Exception:
        return findings

    mappings = _parse_tounicode_cmap(cmap_bytes)
    pua_count = 0

    for src_code, dst_chars in mappings:
        if not dst_chars:
            continue
        dst_ord = ord(dst_chars[0])

        if 0xE000 <= dst_ord <= 0xF8FF or 0xF0000 <= dst_ord <= 0xFFFFD:
            pua_count += 1
            continue

        if 0x20 <= src_code <= 0x7E and 0x20 <= dst_ord <= 0x7E and src_code != dst_ord:
            src_c, dst_c = chr(src_code), dst_chars[0]
            if (src_c.isdigit() and dst_c.isdigit()) or (src_c.isalpha() and dst_c.isalpha()):
                findings.append({
                    "type": "tounicode_remap", "font": font_name, "severity": "critical",
                    "message": f"Font '{font_name}' /ToUnicode remaps '{src_c}' (0x{src_code:02X}) → '{dst_c}' (U+{dst_ord:04X})",
                })

    if pua_count > 0:
        findings.append({
            "type": "tounicode_pua", "font": font_name, "severity": "critical",
            "message": f"Font '{font_name}' /ToUnicode maps {pua_count} character(s) to Private Use Area",
            "pua_count": pua_count,
        })
    return findings


def _get_font_descriptor(font_obj):
    desc = font_obj.get("/FontDescriptor")
    if desc is None:
        desc_fonts = font_obj.get("/DescendantFonts")
        if desc_fonts is not None:
            try:
                desc = desc_fonts[0].get("/FontDescriptor")
            except (IndexError, Exception):
                pass
    return desc


def _check_embedded_font_cmap(font_obj, font_name):
    if TTFont is None:
        return []
    findings = []
    desc = _get_font_descriptor(font_obj)
    if desc is None:
        return findings

    font_bytes = None
    for key in ("/FontFile2", "/FontFile3", "/FontFile"):
        ff = desc.get(key)
        if ff is not None:
            try:
                font_bytes = ff.read_bytes()
            except Exception:
                pass
            break
    if font_bytes is None:
        return findings

    try:
        tt = TTFont(io.BytesIO(font_bytes))
    except Exception:
        return findings

    # Check font name
    try:
        for record in tt["name"].names:
            if record.nameID in (1, 4, 6):
                try:
                    fname = record.toUnicode().lower()
                    if any(m in fname for m in KNOWN_MALICIOUS_NAMES):
                        findings.append({
                            "type": "font_name_suspicious", "font": font_name, "severity": "critical",
                            "message": f"Font '{font_name}' embeds known-malicious font '{record.toUnicode()}'",
                        })
                        break
                except Exception:
                    pass
    except Exception:
        pass

    cmap_table = tt.getBestCmap()
    if cmap_table is None:
        tt.close()
        return findings

    pua_count = 0
    for codepoint, glyph_name in cmap_table.items():
        if 0xE000 <= codepoint <= 0xF8FF or 0xF0000 <= codepoint <= 0xFFFFD:
            pua_count += 1
        elif (0x41 <= codepoint <= 0x5A or 0x61 <= codepoint <= 0x7A):
            expected = chr(codepoint)
            if len(glyph_name) == 1 and glyph_name.isalpha() and glyph_name != expected:
                findings.append({
                    "type": "font_cmap_mismatch", "font": font_name, "severity": "critical",
                    "message": f"Font '{font_name}' glyph '{glyph_name}' mapped to U+{codepoint:04X} ('{expected}')",
                })
        elif 0x30 <= codepoint <= 0x39:
            if len(glyph_name) == 1 and glyph_name.isdigit() and glyph_name != chr(codepoint):
                findings.append({
                    "type": "font_cmap_mismatch", "font": font_name, "severity": "critical",
                    "message": f"Font '{font_name}' glyph '{glyph_name}' mapped to digit '{chr(codepoint)}'",
                })

    if pua_count > 2:
        findings.append({
            "type": "font_cmap_pua", "font": font_name, "severity": "critical",
            "message": f"Font '{font_name}' maps {pua_count} codepoints from Private Use Area",
        })

    tt.close()
    return findings


def _check_actualtext(page):
    findings = []
    try:
        content = page.get("/Contents")
        if content is None:
            return findings
        if isinstance(content, pikepdf.Array):
            raw = b"".join(s.read_bytes() for s in content)
        else:
            raw = content.read_bytes()
    except Exception:
        return findings

    text = raw.decode("latin-1", errors="replace")
    for match in re.finditer(r'/ActualText\s*(?:\(([^)]*)\)|<([0-9a-fA-F]*)>)', text, re.DOTALL):
        literal, hex_text = match.group(1), match.group(2)
        if literal is not None:
            override = literal
        elif hex_text is not None:
            try:
                override = bytes.fromhex(hex_text).decode("utf-16-be", errors="replace")
            except ValueError:
                continue
        else:
            continue
        if override.strip():
            findings.append({
                "type": "actualtext", "severity": "warning",
                "message": f"/ActualText override: extraction reads '{override[:80]}' regardless of display",
            })
    return findings


def _check_encoding_differences(font_obj, font_name):
    findings = []
    encoding = font_obj.get("/Encoding")
    if encoding is None or not isinstance(encoding, pikepdf.Dictionary):
        return findings
    differences = encoding.get("/Differences")
    if differences is None:
        return findings
    try:
        diff_list = list(differences)
    except Exception:
        return findings

    current_code = 0
    remaps = []
    high_byte_glyphs = []

    for item in diff_list:
        if isinstance(item, (int, pikepdf.objects.Object)):
            try:
                current_code = int(item)
            except (ValueError, TypeError):
                pass
        elif isinstance(item, pikepdf.Name):
            glyph_name = str(item).lstrip("/")
            if 0x41 <= current_code <= 0x5A or 0x61 <= current_code <= 0x7A:
                expected = chr(current_code)
                if len(glyph_name) == 1 and glyph_name.isalpha() and glyph_name != expected:
                    remaps.append((current_code, expected, glyph_name))
            elif current_code >= 0x80:
                if len(glyph_name) == 1 and glyph_name.isalnum():
                    high_byte_glyphs.append((current_code, glyph_name))
                elif glyph_name in ("zero","one","two","three","four","five","six","seven","eight","nine"):
                    high_byte_glyphs.append((current_code, glyph_name))
            current_code += 1

    if remaps:
        detail = ", ".join(f"'{s}'→'{t}'" for _, s, t in remaps[:5])
        findings.append({
            "type": "encoding_differences", "font": font_name, "severity": "critical",
            "message": f"Font '{font_name}' /Encoding remaps {len(remaps)} char(s): {detail}",
        })
    if len(high_byte_glyphs) > 5:
        detail = ", ".join(f"0x{p:02X}→'{g}'" for p, g in high_byte_glyphs[:5])
        findings.append({
            "type": "encoding_high_byte_remap", "font": font_name, "severity": "critical",
            "message": f"Font '{font_name}' /Encoding maps {len(high_byte_glyphs)} high-byte positions to standard glyphs: {detail}",
        })
    return findings


def scan_pdf(pdf_path):
    if pikepdf is None:
        return {"file": os.path.basename(pdf_path), "error": "pikepdf not installed",
                "summary": {"total_findings": 0, "critical": 0, "warning": 0}, "findings": []}

    findings = []
    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        return {"file": os.path.basename(pdf_path), "error": str(e),
                "summary": {"total_findings": 0, "critical": 0, "warning": 0}, "findings": []}

    seen_fonts = set()
    for page_num, page in enumerate(pdf.pages, 1):
        for f in _check_actualtext(page):
            f["page"] = page_num
            findings.append(f)

        resources = page.get("/Resources")
        if resources is None:
            continue
        fonts = resources.get("/Font")
        if fonts is None:
            continue

        for font_name_obj in fonts.keys():
            font_name = str(font_name_obj).lstrip("/")
            if font_name in seen_fonts:
                continue
            seen_fonts.add(font_name)
            font_obj = fonts[font_name_obj]

            for check in (_check_tounicode, _check_encoding_differences, _check_embedded_font_cmap):
                for f in check(font_obj, font_name):
                    f["page"] = page_num
                    findings.append(f)

    pdf.close()
    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]
    return {
        "file": os.path.basename(pdf_path),
        "summary": {"total_findings": len(findings), "critical": len(critical), "warning": len(warnings)},
        "findings": findings,
    }
