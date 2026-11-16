# OSINT

## Document author (50)
Evidence: `DN-5583_verhaegen.pdf` (a legitimate supplier delivery note). The question says the
author is **not in the visible text** → it's in the PDF metadata.

```python
from pypdf import PdfReader
md = PdfReader("DN-5583_verhaegen.pdf").metadata
print(md)   # /Title, /Author, /Creator, /Producer
```

The `/Author` field holds the name (`████`). `/Creator` and `/Producer` (`Verhaegen Packaging
ERP`) confirm it's a genuine document from the real supplier's ERP — useful context for the
Email challenges, where the attacker *impersonates* this same supplier with a look-alike domain.
