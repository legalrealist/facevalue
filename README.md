# facevalue

Don't take documents at face value.

Documents can be crafted so that what humans see differs from what extraction tools read. facevalue scans files at the raw structural level — bypassing the same extraction libraries that are vulnerable — and flags divergence before your pipeline trusts the extracted data.

## The problem

A cell in Excel shows `$127,400,000`. Every extraction library reads `146500000`. A PDF displays "State of Maryland". Every text extractor reads "State of Delaware". This is not a rendering quirk — it's an adversarial attack on the assumption that extracted text equals displayed text.

Tested against Claude, ChatGPT, Gemini, and 9 extraction libraries. Zero detected the divergence.

## What it detects

### XLSX
- **Static number format attacks** — cells where the number format is a hardcoded string that doesn't match the raw value

### PDF
- **/ToUnicode CMap remapping** — character-to-Unicode mappings that swap digits or letters
- **Embedded font cmap manipulation** — TrueType fonts with PUA mappings or mismatched glyph names (noroboto)
- **/ActualText overrides** — marked content that silently replaces extracted text
- **/Encoding /Differences** — character position remapping, including high-byte obfuscation patterns

### DOCX
- **Embedded font cmap manipulation** — same noroboto attack with automatic OOXML font de-obfuscation
- **Hidden text** (`<w:vanish>`) — text extractors read but humans don't see
- **Revision marks** — unresolved track changes causing extractor disagreement
- **DDE field codes** — external command execution with misleading cached display
- **AlternateContent blocks** — different content for different consumers

## Install

```bash
pip install lxml pikepdf fonttools
```

## Usage

```bash
python3 facevalue.py document.xlsx
python3 facevalue.py report.pdf
python3 facevalue.py contract.docx
python3 facevalue.py ./documents/
python3 facevalue.py --json document.xlsx
```

## Output

```
[SAFE] No divergence in: financials.xlsx

[DIVERGENCE_DETECTED] 27 finding(s) across 1 XLSX file(s).

STOP. Do not trust numeric values from the flagged file(s).
Displayed values and extracted values differ.

  File: financials_poisoned.xlsx
    [CRITICAL] sheet1!B13: displays '$127,400,000' but raw value is 146500000.0
```

## Claude Code skill

```bash
claude plugin add /path/to/facevalue
```

`/facevalue:scan` runs before document analysis in legal, financial, and compliance workflows.

## Research

- **XLSX attacks**: [lying-spreadsheets](https://github.com/legalrealist/lying-spreadsheets) — static number format deception
- **PDF/DOCX font attacks**: [noroboto](https://github.com/LegalQuants/noroboto) — TrueType cmap manipulation (Tritium/LegalQuants)

## License

MIT
