# ALU Regex Data Extraction & Secure Validation

A Python program that extracts structured data from raw, messy text (as returned by external APIs or CRM exports) using regular expressions. Built with defensive programming in mind — all input is treated as untrusted.

---

## Project Structure

```
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt        # Realistic messy input (contact dirs, tickets, social posts)
├── src/
│   └── main.py             # All extraction and validation logic
├── output/
│   └── sample-output.json  # Structured JSON results
└── README.md
```

---

## How to Run

**Requirements:** Python 3.10+ (uses `str | None` union type syntax)

```bash
# From the project root:
python3 src/main.py
```

Output is printed to the console and written to `output/sample-output.json`.

---

## Data Types Extracted

| # | Type | Notes |
|---|------|-------|
| 1 | **Email addresses** | General + ALU domain validation |
| 2 | **Credit card numbers** | Masked in all output (never logged raw) |
| 3 | **URLs** | `http`/`https` only — `file://`, `javascript:` rejected |
| 4 | **Phone numbers** | International formats, E.164 digit-count validated |
| 5 | **Time values** | 12-hour (`3:47 PM`) and 24-hour (`14:30`) |
| 6 | **Currency amounts** | USD `$`, GBP `£`, EUR `€`, JPY `¥`, NGN `₦` |
| 7 | **Hashtags** | Must start with a letter after `#` |
| 8 | **HTML tags** | Extracted for analysis; `<script>` blocks blocked upstream |

---

## ALU Email Validation

After general extraction, emails are classified by domain:

| Domain | Example |
|--------|---------|
| `@alueducation.com` | `admissions@alueducation.com` |
| `@alumni.alueducation.com` | `j.doe@alumni.alueducation.com` |
| `@si.alueducation.com` | `coordinator@si.alueducation.com` |

The regex checks most-specific subdomains first to avoid misclassification.

---

## Security Design

The program demonstrates the following defensive practices:

### 1. Line-level sanitisation (before any regex runs)
Every line is passed through `sanitise_line()` before extraction:
- Lines over **2,000 characters** are truncated (prevents ReDoS attacks where catastrophic backtracking on long input can hang the process)
- Lines matching **hostile patterns** are rejected entirely and counted

### 2. Hostile pattern detection (`is_hostile()`)
The following are flagged and the line is dropped:

| Threat | Example in input |
|--------|-----------------|
| `<script>` blocks | `<script>document.cookie='hacked'</script>` |
| `javascript:` URIs | `javascript:alert(1)` |
| Inline event handlers | `onclick=...` |
| Path traversal | `../../../../etc/passwd` |
| Local file URIs | `file:///etc/shadow` |
| Control characters / null bytes | `\x00`, `\x1f`, etc. |

### 3. Credit card masking
Card numbers are **never stored, printed, or logged in raw form**. The moment a match is found, `mask_card()` converts it to `**** **** **** 6467`. Test/placeholder numbers (all same digit) are discarded entirely.

### 4. Test card rejection
Numbers like `0000 0000 0000 0000` or `1111 1111 1111 1111` are detected by `is_test_card()` and excluded from results — they indicate bad data or probing.

### 5. Scheme-restricted URL matching
The URL pattern only matches `http://` and `https://`. `file://`, `data:`, `ftp://`, and `javascript:` schemes are not matched by design.

### 6. Phone digit-count validation
After matching, `is_valid_phone()` checks that the digit count falls within the ITU-T E.164 range (7–15 digits), filtering out false positives like version numbers or date strings.

---

## Sample Output (abbreviated)

```json
{
  "meta": {
    "total_lines": 129,
    "safe_lines": 125,
    "hostile_lines_rejected": 4
  },
  "emails": {
    "alu": {
      "alueducation.com": ["admissions@alueducation.com", "..."],
      "alumni.alueducation.com": ["f.wanjiru@alumni.alueducation.com", "..."],
      "si.alueducation.com": ["coordinator@si.alueducation.com", "..."]
    },
    "external": ["jp.hakizimana94@gmail.com", "..."]
  },
  "credit_cards": [
    { "masked": "**** **** **** 6467", "note": "Raw number withheld for security" }
  ]
}
```

See `output/sample-output.json` for the full results.
