# SessLint Fixture Provenance & Data Privacy Rules

To protect privacy and ensure clean-room reproducibility, all test fixtures committed to the SessLint repository must adhere to the following mandatory provenance rules.

---

## 1. Zero Real Data Policy

- **Strict Ban**: No real-world user prompts, private codebases, production transcripts, or real API outputs may ever be committed.
- **Synthetically Generated**: Fixtures must be programmatically generated or handcrafted using synthetic identifiers, placeholder sentences, and reproducible seeds.
- **Consented Data**: Any fixture based on consented external formats must strip all proprietary content, set `contains_real_data: false`, and provide a documented `consent_note`.

---

## 2. Mandatory `PROVENANCE.json`

Every fixture directory containing test artifacts must include a `PROVENANCE.json` file conforming to this structure:

```json
{
  "origin": "synthetic",
  "generator": "sesslint.fixtures",
  "seed": 42,
  "created": "2026-09-06",
  "contains_real_data": false,
  "description": "Deterministic test fixtures generated for unit and integration tests."
}
```

### Schema Requirements:
1. `origin`: Must be either `"synthetic"` or `"consented"`.
2. `contains_real_data`: Must **strictly** be `false`. A value of `true` will immediately fail automated CI gates.
3. `seed`: Integer seed (required when `origin == "synthetic"`).
4. `generator`: Name of the generator script or tool.
5. `created`: ISO date of generation.
6. `description`: Human-readable summary of the fixture set.

---

## 3. Binary Artifacts

Any non-text binary fixture (such as `.bin` files testing multibyte splits or encoding anomalies) must be accompanied by an ASCII description in `PROVENANCE.json` explaining the byte layout.
