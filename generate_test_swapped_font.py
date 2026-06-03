"""Generate a test font with swapped glyph outlines (no PUA, no suspicious name).
This is the hardest variant to detect — requires render+OCR."""

import io
import copy
import pikepdf
from pikepdf import Dictionary, Name, Array
from fontTools.ttLib import TTFont
from fontTools.pens.recordingPen import RecordingPen
from fontTools.pens.ttGlyphPen import TTGlyphPen


def _make_swapped_font():
    """Create a font where glyphs for 'M' and 'D' are swapped, and
    'a' and 'e' are swapped. The cmap is 'correct' — it says
    U+0044 → glyph 'D', but the glyph 'D' actually draws an 'M'.
    No PUA codepoints, no suspicious name — pure outline swap."""
    tt = TTFont("/tmp/noroboto/fonts/liberation-sans-regular.ttf")

    # Strip PUA from all cmap subtables
    for table in tt["cmap"].tables:
        to_remove = [cp for cp in table.cmap if 0xE000 <= cp <= 0xF8FF]
        for cp in to_remove:
            del table.cmap[cp]

    glyf = tt["glyf"]

    swaps = [("D", "M"), ("a", "e")]

    for a, b in swaps:
        glyph_a = copy.deepcopy(glyf[a])
        glyph_b = copy.deepcopy(glyf[b])
        glyf[a] = glyph_b
        glyf[b] = glyph_a

        hmtx = tt["hmtx"]
        w_a = hmtx[a]
        w_b = hmtx[b]
        hmtx[a] = w_b
        hmtx[b] = w_a

    buf = io.BytesIO()
    tt.save(buf)
    tt.close()
    return buf.getvalue()


def _make_tounicode_identity():
    """Identity ToUnicode CMap — maps each code to itself."""
    lines = [
        "/CIDInit /ProcSet findresource begin",
        "12 dict begin",
        "begincmap",
        "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
        "/CMapName /Adobe-Identity-UCS def",
        "/CMapType 2 def",
        "1 begincodespacerange",
        "<0000> <FFFF>",
        "endcodespacerange",
    ]

    chars = list(range(0x20, 0x7F))
    lines.append(f"{len(chars)} beginbfchar")
    for c in chars:
        lines.append(f"<{c:04X}> <{c:04X}>")
    lines.append("endbfchar")
    lines.append("endcmap")
    lines.append("CMapName currentdict /CMap defineresource pop")
    lines.append("end")
    lines.append("end")

    return "\n".join(lines).encode("latin-1")


def generate_swapped_glyph_pdf(path):
    """PDF with swapped glyph outlines. No PUA, no suspicious name,
    no structural signal. Only render+OCR catches this."""
    font_bytes = _make_swapped_font()

    pdf = pikepdf.new()

    font_stream = pdf.make_stream(font_bytes)
    font_stream["/Length1"] = len(font_bytes)

    font_descriptor = Dictionary({
        "/Type": Name("/FontDescriptor"),
        "/FontName": Name("/LiberationSans"),
        "/Flags": 32,
        "/FontBBox": Array([-543, -303, 1301, 979]),
        "/ItalicAngle": 0,
        "/Ascent": 905,
        "/Descent": -212,
        "/CapHeight": 979,
        "/StemV": 80,
        "/FontFile2": font_stream,
    })

    font = Dictionary({
        "/Type": Name("/Font"),
        "/Subtype": Name("/TrueType"),
        "/BaseFont": Name("/LiberationSans"),
        "/FirstChar": 32,
        "/LastChar": 126,
        "/FontDescriptor": pdf.make_indirect(font_descriptor),
        "/ToUnicode": pdf.make_stream(_make_tounicode_identity()),
    })

    resources = Dictionary({"/Font": Dictionary({"/F1": font})})

    # Text that will display wrong: "MD" displays as "DM" because glyphs are swapped
    content = (
        b"BT /F1 14 Tf 72 720 Td "
        b"(Governing Law: State of Maryland) Tj "
        b"0 -20 Td "
        b"(Deal Value: $45,000,000) Tj "
        b"ET"
    )

    page_dict = Dictionary({
        "/Type": Name("/Page"),
        "/MediaBox": Array([0, 0, 612, 792]),
        "/Resources": resources,
        "/Contents": pdf.make_stream(content),
    })
    pdf.pages.append(pikepdf.Page(pdf.make_indirect(page_dict)))
    pdf.save(path)
    print(f"Created: {path}")


if __name__ == "__main__":
    generate_swapped_glyph_pdf("fixtures/report_poisoned_swapped_glyphs.pdf")
