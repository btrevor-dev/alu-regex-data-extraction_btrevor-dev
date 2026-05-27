"""
ALU Regex Data Extraction & Secure Validation

Extracts structured data from raw text using regex patterns.
Validates input defensively — treats all external data as untrusted.

Data types extracted:
  1. Email addresses (general + ALU-domain validation)
  2. Credit card numbers (masked in output for security)
  3. URLs
  4. Phone numbers
  5. Time values (12-hour and 24-hour)
  6. Currency amounts
  7. Hashtags
  8. HTML tags

Security measures:
  - Input length limits to prevent DoS via catastrophic backtracking
  - Control character / null byte detection
  - Script injection pattern detection (XSS)
  - Path traversal detection (../../ style attacks)
  - Local file path rejection (file:// URIs)
  - Credit card numbers are masked before output — never logged raw
"""

import re
import json
import os
from datetime import datetime


# SECURITY: Input sanitisation helpers

# Maximum character length we'll process; beyond this we truncate per-line
# to protect against ReDoS (regular expression denial-of-service) attacks.
MAX_LINE_LENGTH = 2000

# Patterns that signal hostile or malicious input — used to flag lines
# before we attempt to extract data from them.
HOSTILE_PATTERNS = [
    re.compile(r'<script[\s\S]*?>[\s\S]*?</script>', re.IGNORECASE),  # script blocks
    re.compile(r'javascript\s*:', re.IGNORECASE),                      # JS URI scheme
    re.compile(r'on\w+\s*=', re.IGNORECASE),                           # inline event handlers
    re.compile(r'\.\./|\.\.\\'),                                        # path traversal
    re.compile(r'file://', re.IGNORECASE),                              # local file URIs
    re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'),                  # control chars / null bytes
]


def is_hostile(text: str) -> bool:
    """
    Returns True if the text contains any pattern associated with
    injection attacks, path traversal, or other hostile content.
    We check BEFORE extracting so malicious strings are never processed
    as legitimate data.
    """
    for pattern in HOSTILE_PATTERNS:
        if pattern.search(text):
            return True
    return False


def sanitise_line(line: str) -> str | None:
    """
    Truncates over-long lines and returns None for hostile ones.
    Returns the (possibly truncated) line if it is safe to process.
    """
    line = line[:MAX_LINE_LENGTH]   # hard truncate — prevent ReDoS
    if is_hostile(line):
        return None
    return line


# REGEX PATTERNS

# 1. Email
# Matches standard email addresses.
# Character classes are intentionally conservative to avoid matching
# obfuscated or malformed addresses that might be used for injection.
PATTERN_EMAIL = re.compile(
    r'\b[a-zA-Z0-9]'            # must start with alnum (not a dot or special)
    r'[a-zA-Z0-9._%+\-]{0,62}'  # local part body (length-limited)
    r'@'
    r'[a-zA-Z0-9.\-]+'          # domain
    r'\.[a-zA-Z]{2,10}\b'       # TLD (2–10 chars is realistic)
)

# ALU domain variants — validated separately after extraction.
# Order matters: most-specific subdomains must come first.
ALU_DOMAIN_PATTERN = re.compile(
    r'@(alumni\.alueducation\.com|si\.alueducation\.com|alueducation\.com)$',
    re.IGNORECASE
)

def is_alu_email(email: str) -> str | None:
    """Returns the matched ALU domain string, or None if not an ALU address."""
    m = ALU_DOMAIN_PATTERN.search(email)
    return m.group(1).lower() if m else None


# 2. Credit card
# Matches common 13–16 digit card formats with optional spaces or dashes.
# Supports Visa (16d), Mastercard (16d), Amex (15d), and Discover (16d).
# Security: numbers are NEVER stored or output raw — see mask_card().
PATTERN_CREDIT_CARD = re.compile(
    r'\b'
    r'(?:'
    r'4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}'  # Visa 16d
    r'|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}'  # MC 16d
    r'|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}'             # Amex 15d
    r'|6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}'  # Discover
    r')'
    r'\b'
)

def mask_card(raw: str) -> str:
    """
    Strips non-digits and returns a masked string showing only the last 4.
    This is the ONLY form in which card data appears in output or logs.
    """
    digits = re.sub(r'\D', '', raw)
    if len(digits) < 4:
        return '****'
    return '**** **** **** ' + digits[-4:]

def is_test_card(raw: str) -> bool:
    """
    Rejects well-known test/placeholder card numbers that should never
    appear in real data (e.g. 0000 0000 0000 0000, 1111 1111 1111 1111).
    """
    digits = re.sub(r'\D', '', raw)
    if len(set(digits)) == 1:   # all same digit
        return True
    return False


# 3. URL
# Matches http/https URLs only. We deliberately exclude ftp://, file://,
# data:, and javascript: schemes as these are common attack vectors.
PATTERN_URL = re.compile(
    r'\bhttps?://'              # scheme — http or https only
    r'(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]){3,2000}'  # path (length-limited)
    r'(?<![.,;:\'\")\]])',      # strip common trailing punctuation
    re.IGNORECASE
)


# 4. Phone number
# Handles international (+) and domestic formats with varied separators.
# Minimum 7 digits, maximum 15 (ITU-T E.164 limit).
PATTERN_PHONE = re.compile(
    r'\b'
    r'(?:\+\d{1,3}[\s\-.]?)?'  # optional country code
    r'(?:\(\d{1,4}\)[\s\-.]?)?'  # optional area code in parens
    r'\d{1,4}'                  # first digit group
    r'(?:[\s\-.]?\d{1,4}){2,4}'  # 2–4 more groups
    r'\b'
)

def is_valid_phone(raw: str) -> bool:
    """Validates digit count is within E.164 range (7–15 digits)."""
    digits = re.sub(r'\D', '', raw)
    return 7 <= len(digits) <= 15


# 5. Time (12-hour and 24-hour)
PATTERN_TIME = re.compile(
    r'\b'
    r'(?:'
    r'(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?'      # 24-hour: 09:15, 14:30:00
    r'|'
    r'(?:1[0-2]|0?[1-9]):[0-5]\d\s?(?:AM|PM|am|pm)'  # 12-hour: 3:47 PM, 11:59 PM
    r')'
    r'\b'
)


# 6. Currency 
# Matches major currency symbols followed by amounts with optional thousands separators.
PATTERN_CURRENCY = re.compile(
    r'(?:USD\s?|GBP\s?|EUR\s?|[\$£€¥₦₹])'  # symbol or code
    r'\d{1,12}'                               # integer part (length-limited)
    r'(?:[,\.]\d{1,3})*'                      # optional thousands/decimal groups
    r'(?:\.\d{2})?'                            # optional cents
)


# 7. Hashtag
PATTERN_HASHTAG = re.compile(
    r'#[a-zA-Z]\w{1,99}'  # must start with a letter after #; max 100 chars
)


# 8. HTML tag
# Matches opening, closing, and self-closing tags.
# NOTE: We extract these for inventory/analysis purposes only.
# Script tags are still flagged as hostile by is_hostile() above.
PATTERN_HTML_TAG = re.compile(
    r'</?[a-zA-Z][a-zA-Z0-9]*'   # tag name
    r'(?:\s[^<>]{0,200})?'        # optional attributes (length-limited)
    r'/?>'                         # closing
)


# EXTRACTION ENGINE

def extract_all(text: str) -> dict:
    """
    Runs all extraction passes over the input text.
    Returns a structured dict of results with metadata.
    Hostile lines are counted and excluded from extraction.
    """
    lines = text.splitlines()
    hostile_count = 0
    safe_lines = []

    for line in lines:
        clean = sanitise_line(line)
        if clean is None:
            hostile_count += 1
        else:
            safe_lines.append(clean)

    safe_text = '\n'.join(safe_lines)

    # Emails
    raw_emails = PATTERN_EMAIL.findall(safe_text)
    emails = {
        'all': [],
        'alu': {
            'alueducation.com': [],
            'alumni.alueducation.com': [],
            'si.alueducation.com': [],
        },
        'external': [],
    }
    seen_emails = set()
    for email in raw_emails:
        email_lower = email.lower()
        if email_lower in seen_emails:
            continue
        seen_emails.add(email_lower)
        emails['all'].append(email)
        domain = is_alu_email(email)
        if domain:
            emails['alu'][domain].append(email)
        else:
            emails['external'].append(email)

    # Credit cards (masked immediately)
    raw_cards = PATTERN_CREDIT_CARD.findall(safe_text)
    credit_cards = []
    seen_cards = set()
    for card in raw_cards:
        if is_test_card(card):
            # Known test/placeholder numbers — log the event but discard
            continue
        masked = mask_card(card)
        if masked not in seen_cards:
            seen_cards.add(masked)
            credit_cards.append({
                'masked': masked,
                'note': 'Raw number withheld for security'
            })

    # URLs
    raw_urls = PATTERN_URL.findall(safe_text)
    urls = list(dict.fromkeys(raw_urls))  # deduplicate, preserve order

    # Phone numbers
    raw_phones = PATTERN_PHONE.findall(safe_text)
    phones = list(dict.fromkeys(
        p for p in raw_phones if is_valid_phone(p)
    ))

    # Times
    times = list(dict.fromkeys(PATTERN_TIME.findall(safe_text)))

    # Currency
    currencies = list(dict.fromkeys(PATTERN_CURRENCY.findall(safe_text)))

    # Hashtags
    hashtags = list(dict.fromkeys(PATTERN_HASHTAG.findall(safe_text)))

    # HTML tags
    html_tags = list(dict.fromkeys(PATTERN_HTML_TAG.findall(safe_text)))

    return {
        'meta': {
            'extracted_at': datetime.utcnow().isoformat() + 'Z',
            'total_lines': len(lines),
            'safe_lines': len(safe_lines),
            'hostile_lines_rejected': hostile_count,
        },
        'emails': emails,
        'credit_cards': credit_cards,
        'urls': urls,
        'phone_numbers': phones,
        'times': times,
        'currency_amounts': currencies,
        'hashtags': hashtags,
        'html_tags': html_tags,
    }


# ENTRY POINT

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path  = os.path.join(base_dir, 'input', 'raw-text.txt')
    output_path = os.path.join(base_dir, 'output', 'sample-output.json')

    print(f'[*] Reading input from: {input_path}')
    with open(input_path, 'r', encoding='utf-8') as f:
        raw_text = f.read()

    print(f'[*] Input length: {len(raw_text):,} characters')
    print('[*] Running extraction...\n')

    results = extract_all(raw_text)

    # Console summary
    m = results['meta']
    print('=' * 60)
    print('  EXTRACTION SUMMARY')
    print('=' * 60)
    print(f"  Lines processed : {m['safe_lines']} / {m['total_lines']}")
    print(f"  Hostile rejected: {m['hostile_lines_rejected']}")
    print(f"  Extracted at    : {m['extracted_at']}")
    print('-' * 60)

    e = results['emails']
    print(f"\n  EMAILS ({len(e['all'])} total)")
    print(f"    ALU (alueducation.com)        : {len(e['alu']['alueducation.com'])}")
    print(f"    ALU (alumni.alueducation.com) : {len(e['alu']['alumni.alueducation.com'])}")
    print(f"    ALU (si.alueducation.com)     : {len(e['alu']['si.alueducation.com'])}")
    print(f"    External                       : {len(e['external'])}")

    print(f"\n  CREDIT CARDS   : {len(results['credit_cards'])} (all masked)")
    print(f"  URLs           : {len(results['urls'])}")
    print(f"  PHONE NUMBERS  : {len(results['phone_numbers'])}")
    print(f"  TIMES          : {len(results['times'])}")
    print(f"  CURRENCY       : {len(results['currency_amounts'])}")
    print(f"  HASHTAGS       : {len(results['hashtags'])}")
    print(f"  HTML TAGS      : {len(results['html_tags'])}")
    print('=' * 60)

    # Write JSON output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f'\n[+] Full results written to: {output_path}')


if __name__ == '__main__':
    main()