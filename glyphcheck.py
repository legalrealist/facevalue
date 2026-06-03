"""
glyphcheck.py -- Render-and-OCR verification for embedded font glyphs.

Catches the hardest parser differential variant: fonts where the glyph
outlines have been swapped so a character LOOKS like one thing but the
cmap says it's another. No structural signal exists — the only way to
detect it is to render the glyph and see what it actually looks like.

Approach (same as Tritium's noroboto mitigation):
  1. Extract the embedded font binary
  2. Render each alphanumeric glyph to a bitmap at 72pt
  3. OCR the bitmap with tesseract
  4. Compare OCR result to the cmap's Unicode mapping
  5. If they disagree, the font is lying
"""

import io
import os
import tempfile

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None

try:
    import pytesseract
except ImportError:
    pytesseract = None

try:
    from fontTools.ttLib import TTFont
except ImportError:
    TTFont = None

CHARS_TO_CHECK = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _render_glyph(font_bytes, char, size=72):
    """Render a single character using the font, return a PIL Image."""
    tmpdir = os.path.dirname(os.path.abspath(__file__))
    tmp_path = os.path.join(tmpdir, ".glyphcheck_tmp.ttf")

    try:
        with open(tmp_path, "wb") as f:
            f.write(font_bytes)

        pil_font = ImageFont.truetype(tmp_path, size)
        bbox = pil_font.getbbox(char)
        if bbox is None:
            return None

        padding = 16
        w = bbox[2] - bbox[0] + padding * 2
        h = bbox[3] - bbox[1] + padding * 2

        if w < 4 or h < 4:
            return None

        img = Image.new("L", (w, h), 255)
        draw = ImageDraw.Draw(img)
        draw.text((padding - bbox[0], padding - bbox[1]), char, font=pil_font, fill=0)
        return img
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _ocr_glyph(img):
    """OCR a single-character image, return the recognized character."""
    tmpdir = os.path.dirname(os.path.abspath(__file__))
    img_path = os.path.join(tmpdir, ".glyphcheck_tmp.png")
    out_path = os.path.join(tmpdir, ".glyphcheck_tmp_out")

    try:
        img.save(img_path)
        import subprocess
        result = subprocess.run(
            ["tesseract", img_path, out_path, "--psm", "10",
             "-c", "tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"],
            capture_output=True, timeout=10,
        )
        txt_path = out_path + ".txt"
        if os.path.exists(txt_path):
            with open(txt_path) as f:
                text = f.read().strip()
            os.unlink(txt_path)
            return text[:1] if text else ""
        return ""
    except Exception:
        return ""
    finally:
        try:
            os.unlink(img_path)
        except OSError:
            pass


def check_font(font_bytes, font_name="unknown"):
    """Verify that a font's glyphs match its cmap by rendering + OCR.
    Returns list of findings where the rendered glyph disagrees with the cmap."""
    if Image is None or pytesseract is None or TTFont is None:
        return []

    findings = []

    try:
        tt = TTFont(io.BytesIO(font_bytes))
    except Exception:
        return findings

    cmap = tt.getBestCmap()
    if cmap is None:
        tt.close()
        return findings

    mismatches = []
    checked = 0

    for char in CHARS_TO_CHECK:
        codepoint = ord(char)
        if codepoint not in cmap:
            continue

        img = _render_glyph(font_bytes, char)
        if img is None:
            continue

        checked += 1
        ocr_result = _ocr_glyph(img)

        if not ocr_result:
            continue

        if ocr_result != char:
            # Case-insensitive tolerance for OCR ambiguity (l/I, O/0)
            if ocr_result.lower() == char.lower():
                continue
            # Common OCR confusions that aren't attacks
            if (char, ocr_result) in (
                ("l", "1"), ("1", "l"), ("I", "l"), ("l", "I"),
                ("O", "0"), ("0", "O"), ("Q", "O"),
                ("S", "5"), ("5", "S"), ("Z", "2"), ("2", "Z"),
                ("B", "8"), ("8", "B"), ("G", "6"), ("6", "G"),
            ):
                continue

            mismatches.append({
                "codepoint": codepoint,
                "expected": char,
                "ocr_result": ocr_result,
            })

    tt.close()

    if mismatches and checked > 0:
        mismatch_rate = len(mismatches) / checked
        # Only flag if enough mismatches to rule out OCR noise
        if len(mismatches) >= 3 or mismatch_rate > 0.15:
            sample = mismatches[:8]
            detail = ", ".join(
                f"'{m['expected']}'→'{m['ocr_result']}'" for m in sample
            )
            findings.append({
                "type": "glyph_ocr_mismatch",
                "font": font_name,
                "severity": "critical",
                "message": (
                    f"Font '{font_name}' renders glyphs that disagree with its "
                    f"cmap: {len(mismatches)}/{checked} characters mismatch "
                    f"({detail})"
                ),
                "mismatches": mismatches,
                "checked": checked,
            })

    return findings


def is_available():
    """Check if glyph verification dependencies are installed."""
    return Image is not None and pytesseract is not None and TTFont is not None
