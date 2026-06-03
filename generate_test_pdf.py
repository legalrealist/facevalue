"""Generate test PDF fixtures with and without font manipulation."""

import pikepdf
from pikepdf import Dictionary, Name, Array, String


def _make_tounicode_cmap(remaps):
    """Build a ToUnicode CMap stream that remaps characters."""
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
        f"{len(remaps)} beginbfchar",
    ]
    for src_code, dst_code in remaps:
        lines.append(f"<{src_code:04X}> <{dst_code:04X}>")
    lines.extend([
        "endbfchar",
        "endcmap",
        "CMapName currentdict /CMap defineresource pop",
        "end",
        "end",
    ])
    return "\n".join(lines).encode("latin-1")


def _add_page(pdf, resources_dict, content_bytes):
    """Add a page to a pikepdf document."""
    page_dict = Dictionary({
        "/Type": Name("/Page"),
        "/MediaBox": Array([0, 0, 612, 792]),
        "/Resources": resources_dict,
        "/Contents": pdf.make_stream(content_bytes),
    })
    pdf.pages.append(pikepdf.Page(pdf.make_indirect(page_dict)))


def generate_clean_pdf(path):
    """Generate a normal PDF with no font manipulation."""
    pdf = pikepdf.new()

    resources = Dictionary({
        "/Font": Dictionary({
            "/F1": Dictionary({
                "/Type": Name("/Font"),
                "/Subtype": Name("/Type1"),
                "/BaseFont": Name("/Helvetica"),
            })
        })
    })

    _add_page(pdf, resources, b"BT /F1 12 Tf 72 720 Td (Revenue: $127,400,000) Tj ET")
    pdf.save(path)
    print(f"Created: {path}")


def generate_poisoned_tounicode_pdf(path):
    """Generate a PDF with /ToUnicode CMap that remaps digits."""
    pdf = pikepdf.new()

    # Remap: display "1" but extract "9", display "2" but extract "4", etc.
    remaps = [
        (0x31, 0x39),  # '1' -> '9'
        (0x32, 0x34),  # '2' -> '4'
        (0x37, 0x31),  # '7' -> '1'
        (0x34, 0x38),  # '4' -> '8'
    ]

    # Build all other chars as identity
    identity = [(i, i) for i in range(0x20, 0x7F) if i not in [r[0] for r in remaps]]
    all_remaps = identity + remaps

    cmap_data = _make_tounicode_cmap(all_remaps)

    font = Dictionary({
        "/Type": Name("/Font"),
        "/Subtype": Name("/Type1"),
        "/BaseFont": Name("/Helvetica"),
        "/ToUnicode": pdf.make_stream(cmap_data),
    })

    resources = Dictionary({"/Font": Dictionary({"/F1": font})})
    _add_page(pdf, resources, b"BT /F1 12 Tf 72 720 Td (Revenue: $127,400,000) Tj ET")
    pdf.save(path)
    print(f"Created: {path}")


def generate_actualtext_pdf(path):
    """Generate a PDF with /ActualText override."""
    pdf = pikepdf.new()

    font = Dictionary({
        "/Type": Name("/Font"),
        "/Subtype": Name("/Type1"),
        "/BaseFont": Name("/Helvetica"),
    })

    resources = Dictionary({"/Font": Dictionary({"/F1": font})})
    content = (
        b"BT /F1 12 Tf 72 720 Td "
        b"/Span <</ActualText (Delaware)>> BDC "
        b"(Maryland) Tj "
        b"EMC "
        b"ET"
    )
    _add_page(pdf, resources, content)
    pdf.save(path)
    print(f"Created: {path}")


if __name__ == "__main__":
    generate_clean_pdf("fixtures/report_clean.pdf")
    generate_poisoned_tounicode_pdf("fixtures/report_poisoned_tounicode.pdf")
    generate_actualtext_pdf("fixtures/report_poisoned_actualtext.pdf")
