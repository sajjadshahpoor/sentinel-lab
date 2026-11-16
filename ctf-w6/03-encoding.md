# Encoding

## Stage 2 — Peel three layers (150)
Evidence: `stage2.b64.txt` (161 bytes). Base64 is the outer layer, but it decodes to 119 bytes of
high-entropy binary that is **not** gzip/zlib/bz2/lzma/brotli/zstd/lz4 — so the middle layer is a
keyed transform, not a plain codec.

**Method.** I built a small recursive peeler that, at each layer, tries every common codec
(base64/32/85, hex, gzip/zlib/raw-inflate/bz2/lzma) **and** a dictionary of XOR keys themed to the
incident (`fire`, `tir`, `hamilton`, `stage2`, …). It searches until a layer contains `HAM{`.

The winning recipe:

```
From Base64  →  XOR key "hamilton"  →  Gunzip  →  HAM{████}
```

The key insight: after the Base64 layer the bytes looked compressed but every decompressor
failed — that's the signature of a cipher sitting *between* two codecs. Guessing a short,
theme-based repeating XOR key (`hamilton`, the domain) turned the blob into a valid gzip stream.
