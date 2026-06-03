# SheetGuard

Document parser differential scanner. Detects attacks where displayed content
differs from what extraction tools read — across XLSX, PDF, and DOCX.

Covers: XLSX static number formats, PDF /ToUnicode remapping, PDF/DOCX embedded
font cmap manipulation (noroboto), /ActualText overrides, DOCX hidden text,
revision marks, field codes, and alternate content blocks.

## Quick start

```bash
python3 sheetguard.py <file.xlsx|file.pdf|file.docx|directory>
```

## When to use

Run `/sheetguard:scan` before trusting extracted values from XLSX, PDF, or DOCX
files, especially in financial, legal, or compliance workflows.

## Dependencies

- Python 3.8+
- lxml (`pip install lxml`) — XLSX and DOCX scanning
- pikepdf (`pip install pikepdf`) — PDF scanning
- fonttools (`pip install fonttools`) — embedded font analysis (optional)
