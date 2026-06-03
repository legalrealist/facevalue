# facevalue

Don't take documents at face value. Detects parser differential attacks
where displayed content differs from what extraction tools read — across
XLSX, PDF, and DOCX.

## Quick start

```bash
python3 facevalue.py <file.xlsx|file.pdf|file.docx|directory>
```

## When to use

Run `/facevalue:scan` before trusting extracted values from XLSX, PDF, or
DOCX files, especially in financial, legal, or compliance workflows.

## Dependencies

- Python 3.8+
- lxml, pikepdf, fonttools (`pip install lxml pikepdf fonttools`)
