"""Generate test DOCX fixtures with and without manipulation."""

import os
import zipfile
from lxml import etree

WML_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
PKG_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

NSMAP = {"w": WML_NS, "r": REL_NS}


def _content_types():
    root = etree.Element("Types", xmlns=CT_NS)
    etree.SubElement(root, "Default", Extension="rels",
                     ContentType="application/vnd.openxmlformats-package.relationships+xml")
    etree.SubElement(root, "Default", Extension="xml",
                     ContentType="application/xml")
    etree.SubElement(root, "Override", PartName="/word/document.xml",
                     ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _rels():
    root = etree.Element("Relationships", xmlns=PKG_NS)
    etree.SubElement(root, "Relationship", Id="rId1",
                     Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
                     Target="word/document.xml")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _word_rels():
    root = etree.Element("Relationships", xmlns=PKG_NS)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _make_paragraph(text, hidden=False):
    p = etree.SubElement(etree.Element("dummy"), f"{{{WML_NS}}}p")
    r = etree.SubElement(p, f"{{{WML_NS}}}r")
    if hidden:
        rpr = etree.SubElement(r, f"{{{WML_NS}}}rPr")
        etree.SubElement(rpr, f"{{{WML_NS}}}vanish")
    t = etree.SubElement(r, f"{{{WML_NS}}}t")
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    t.text = text
    return p


def generate_clean_docx(path):
    body = etree.Element(f"{{{WML_NS}}}body")
    body.append(_make_paragraph("Governing Law: State of Maryland"))
    body.append(_make_paragraph("Revenue: $127,400,000"))

    doc = etree.Element(f"{{{WML_NS}}}document", nsmap=NSMAP)
    doc.append(body)
    doc_bytes = etree.tostring(doc, xml_declaration=True, encoding="UTF-8")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types())
        z.writestr("_rels/.rels", _rels())
        z.writestr("word/_rels/document.xml.rels", _word_rels())
        z.writestr("word/document.xml", doc_bytes)
    print(f"Created: {path}")


def generate_hidden_text_docx(path):
    body = etree.Element(f"{{{WML_NS}}}body")
    body.append(_make_paragraph("Governing Law: State of Maryland"))
    body.append(_make_paragraph(
        "CONFIDENTIAL: Actual governing law is Delaware per side letter dated 2024-01-15",
        hidden=True
    ))
    body.append(_make_paragraph("Revenue: $127,400,000"))

    doc = etree.Element(f"{{{WML_NS}}}document", nsmap=NSMAP)
    doc.append(body)
    doc_bytes = etree.tostring(doc, xml_declaration=True, encoding="UTF-8")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types())
        z.writestr("_rels/.rels", _rels())
        z.writestr("word/_rels/document.xml.rels", _word_rels())
        z.writestr("word/document.xml", doc_bytes)
    print(f"Created: {path}")


def generate_revision_marks_docx(path):
    body = etree.Element(f"{{{WML_NS}}}body")

    # Normal paragraph
    body.append(_make_paragraph("Agreement between PartyA and PartyB"))

    # Paragraph with tracked deletion and insertion
    p = etree.SubElement(body, f"{{{WML_NS}}}p")

    # Normal text
    r1 = etree.SubElement(p, f"{{{WML_NS}}}r")
    t1 = etree.SubElement(r1, f"{{{WML_NS}}}t")
    t1.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    t1.text = "Liability cap: "

    # Deleted text (hidden visually but in XML)
    del_elem = etree.SubElement(p, f"{{{WML_NS}}}del",
                                 attrib={f"{{{WML_NS}}}id": "1",
                                         f"{{{WML_NS}}}author": "Legal",
                                         f"{{{WML_NS}}}date": "2024-06-01T10:00:00Z"})
    del_r = etree.SubElement(del_elem, f"{{{WML_NS}}}r")
    del_t = etree.SubElement(del_r, f"{{{WML_NS}}}delText")
    del_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    del_t.text = "$50,000,000"

    # Inserted text (the replacement)
    ins_elem = etree.SubElement(p, f"{{{WML_NS}}}ins",
                                 attrib={f"{{{WML_NS}}}id": "2",
                                         f"{{{WML_NS}}}author": "Legal",
                                         f"{{{WML_NS}}}date": "2024-06-01T10:00:00Z"})
    ins_r = etree.SubElement(ins_elem, f"{{{WML_NS}}}r")
    ins_t = etree.SubElement(ins_r, f"{{{WML_NS}}}t")
    ins_t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    ins_t.text = "$10,000,000"

    doc = etree.Element(f"{{{WML_NS}}}document", nsmap=NSMAP)
    doc.append(body)
    doc_bytes = etree.tostring(doc, xml_declaration=True, encoding="UTF-8")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types())
        z.writestr("_rels/.rels", _rels())
        z.writestr("word/_rels/document.xml.rels", _word_rels())
        z.writestr("word/document.xml", doc_bytes)
    print(f"Created: {path}")


if __name__ == "__main__":
    generate_clean_docx("fixtures/contract_clean.docx")
    generate_hidden_text_docx("fixtures/contract_poisoned_hidden.docx")
    generate_revision_marks_docx("fixtures/contract_poisoned_revisions.docx")
