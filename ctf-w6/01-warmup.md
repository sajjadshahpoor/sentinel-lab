# Warm-up

Pure encoding puzzles — the data is in the challenge text, no evidence download. Everything here
is reversible (encoding, not encryption), so each is a short CyberChef recipe (I did them in
Python to keep a record).

## Warm-up 1 — Base64 (50)
Input: `SEFNe2I2NF9pc19qdXN0X2VuY29kaW5nfQ==`. A single Base64 layer.
```python
import base64; base64.b64decode("SEFNe2I2NF9pc19qdXN0X2VuY29kaW5nfQ==")
```
→ `HAM{████}` (a plain base64 of the flag — the lesson is "encoding ≠ encryption").

## Warm-up 2 — ROT13 + hex (50)
Input: `554e5a7b...75726b7d`. Two reversible layers: hex, then a letter rotation.
```python
import codecs; codecs.decode(bytes.fromhex("554e5a7b65626731335f637968665f75726b7d").decode(), "rot_13")
```
Hex → `UNZ{ebg13_cyhf_urk}`, then ROT13 → `HAM{████}`.

## Warm-up 3 — Windows FILETIME (50)
Input FILETIME `133758548410000000` (100-ns intervals since 1601-01-01 UTC). Convert to Unix epoch:
`FILETIME / 10_000_000 − 11_644_473_600`.
```python
133758548410000000 // 10_000_000 - 11644473600   # -> 1731381241
```
Answer: the Unix epoch in whole seconds (`████████`, ≈ 2024-11-12). Not a `HAM{}` flag — a number.

## Warm-up 4 — Peel the recipe (100)
Input is URL-encoded. The `H4sI` after URL-decoding is the Base64 of a gzip stream.
Recipe: **URL-decode → From Base64 → Gunzip**.
```python
import base64, gzip, urllib.parse
gzip.decompress(base64.b64decode(urllib.parse.unquote(RAW)))
```
→ `HAM{████}`.
