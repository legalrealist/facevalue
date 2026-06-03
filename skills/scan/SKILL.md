---
name: scan
description: >
  Don't take documents at face value. Scan XLSX, PDF, and DOCX files for parser
  differential attacks — where displayed content differs from what extraction tools
  read. Detects XLSX static number format deception, PDF /ToUnicode and font cmap
  manipulation (noroboto-style), /ActualText overrides, DOCX hidden text, revision
  marks, and field codes. Use whenever checking document integrity, before analyzing
  financials or extracting data from contracts, when doing due diligence on documents
  from counterparties, or when the user mentions "facevalue", "format divergence",
  "parser differential", "poisoned spreadsheet", "font manipulation", or "noroboto".
  Use proactively before trusting extracted values from any XLSX, PDF, or DOCX in a
  legal, financial, or compliance context.
---

# facevalue — Document Parser Differential Scanner

## How to use

```bash
python3 {{SKILL_PATH}}/../../facevalue.py <path-to-file-or-directory>
```

Handles XLSX, PDF, and DOCX. For JSON output add `--json`.

Dependencies: `pip install lxml pikepdf fonttools`

## Reading the output

- **`[SAFE]`** — No divergence detected.
- **`[WARNING]`** — Suspicious elements found. Review before trusting.
- **`[DIVERGENCE_DETECTED]`** — Displayed content differs from extracted data.

## When `[DIVERGENCE_DETECTED]` fires

This is a hard stop. Do not proceed to analyze the file's data. Instead:

1. Report the divergence to the user with details from the scan
2. Explain that what humans see differs from what extraction tools read
3. Recommend manual inspection of the flagged elements
4. Do not attempt to "correct" the values

## When to run proactively

- Before financial analysis of documents from external parties
- Before due diligence extraction (revenue, valuation, cap tables, governing law)
- When the user uploads an XLSX, PDF, or DOCX and asks to analyze or extract data
- When processing documents from untrusted sources in legal or compliance workflows

## Test fixtures

In `{{SKILL_PATH}}/../../fixtures/`:

- `financials_clean.xlsx` — should return `[SAFE]`
- `financials_poisoned.xlsx` — XLSX format divergence
