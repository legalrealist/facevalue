---
name: scan
description: >
  Scan XLSX, PDF, and DOCX files for parser differential attacks — where displayed
  content differs from what extraction tools read. Detects XLSX static number format
  deception, PDF /ToUnicode CMap remapping, PDF/DOCX embedded font cmap manipulation
  (noroboto-style), /ActualText overrides, DOCX hidden text, revision marks, field
  codes, and alternate content blocks. Use whenever checking document integrity,
  before analyzing spreadsheet financials or extracting data from PDFs/contracts,
  when doing due diligence on documents from counterparties, or when the user
  mentions "sheetguard", "format divergence", "parser differential", "poisoned
  spreadsheet", "font manipulation", "noroboto", or "hidden text". Use proactively
  before trusting extracted values from any XLSX, PDF, or DOCX in a legal, financial,
  or compliance context.
---

# SheetGuard: Document Parser Differential Scanner

## What this detects

### XLSX: Static number format attacks

XLSX files can contain cells where the **number format is a static string** — the cell
displays "$127,400,000" but the raw XML value is `146500000`. Every extraction library
(openpyxl, pandas, xlrd, CalamineReader) reads the raw value. Excel and Google Sheets
show the formatted value.

### PDF: Font-level manipulation

Three attack surfaces that decouple displayed text from extracted text:

1. **/ToUnicode CMap remapping** — PDF-level mapping override. Extraction reads "9"
   where the font displays "1".
2. **Embedded font cmap manipulation (noroboto)** — TrueType/OpenType `cmap` tables
   map glyph IDs to wrong Unicode, or to Private Use Area codepoints (garbage).
3. **/ActualText overrides** — Marked content operators silently replace extracted text.
   Document displays "Maryland" but extraction reads "Delaware".

### DOCX: Font and structure manipulation

Five attack surfaces:

1. **Embedded font cmap manipulation** — Same noroboto attack as PDF. The DOCX XML
   contains one set of Unicode, but the embedded font renders different glyphs.
   OOXML font obfuscation (XOR scheme) is reversed automatically.
2. **Hidden text (`<w:vanish>`)** — Text present in XML but not rendered. Extractors
   read it, humans don't see it. Used to inject shadow clauses or terms.
3. **Revision marks (`<w:ins>`, `<w:del>`)** — Deleted text is hidden visually but
   persists in XML. Some extractors include it, others skip it, creating divergence.
4. **Field codes** — DDE/MERGEFIELD instructions whose cached display value differs
   from the underlying code.
5. **AlternateContent blocks** — Different content for different consumers.

These are not hypothetical attacks. They work against Claude, ChatGPT, Gemini, and
every document extraction pipeline tested.

## How to use

Run sheetguard.py against any file or directory (handles XLSX, PDF, and DOCX):

```bash
python3 {{SKILL_PATH}}/../../sheetguard.py <path-to-file-or-directory>
```

For JSON output:

```bash
python3 {{SKILL_PATH}}/../../sheetguard.py --json <path-to-file-or-directory>
```

Dependencies: `pip install lxml pikepdf fonttools`

## Reading the output

- **`[SAFE]`** — No divergence detected. File can be trusted.
- **`[WARNING]`** — Suspicious elements found. Review before trusting.
- **`[DIVERGENCE_DETECTED]`** — Critical: displayed content differs from extracted data.

## When `[DIVERGENCE_DETECTED]` fires

This is a hard stop. Do not proceed to analyze the file's data. Instead:

1. Report the divergence to the user with details from the scan
2. Explain that the file contains content where what humans see differs from what
   extraction tools read
3. Recommend the user inspect the flagged elements manually
4. Do not attempt to "correct" the values

## When to run this skill proactively

- Before any financial analysis of documents received from external parties
- Before due diligence extraction (revenue, valuation, cap tables, governing law)
- Before any workflow that makes decisions based on extracted document data
- When the user uploads an XLSX, PDF, or DOCX and asks to "analyze", "summarize",
  or "extract" data from it
- When processing documents from untrusted sources in legal or compliance workflows

## Limitations

- XLSX: static number format attacks only. Macro/formula attacks out of scope.
- PDF: /ToUnicode, font cmap, /ActualText, /Encoding /Differences. Does not cover
  PDFuzz-style operator reordering.
- DOCX: embedded fonts, hidden text, revisions, field codes, AlternateContent.
  Does not cover macro-based attacks.
- Does not cover XLS (legacy binary), CSV, or RTF.
- Font cmap analysis requires `fonttools`. Without it, only structural checks run.

## Test fixtures

In `{{SKILL_PATH}}/../../fixtures/`:

**XLSX:** `financials_clean.xlsx`, `financials_poisoned.xlsx`, `emissions_clean.xlsx`,
`emissions_poisoned.xlsx`

**PDF:** `report_clean.pdf`, `report_poisoned_tounicode.pdf`,
`report_poisoned_actualtext.pdf`

**DOCX:** `contract_clean.docx`, `contract_poisoned_hidden.docx`,
`contract_poisoned_revisions.docx`
