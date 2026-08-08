"""
strength.py
Heuristic password strength and entropy estimation.

IMPORTANT LIMITATION: This is a local, offline HEURISTIC. It approximates
entropy assuming a uniform-random character choice from the detected
charset. It does NOT check the password against real breach corpora,
does NOT model targeted/dictionary attacks, and a high score here is
NOT a guarantee the password is uncrackable. Treat it as guidance only.
"""

import math
import re

_REPEAT_RE = re.compile(r"(.)\1{2,}")
_SEQUENCES = "abcdefghijklmnopqrstuvwxyz0123456789"


def charset_size(password):
    """Estimate the size of the character space the password draws from."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32
    return size


def estimate_entropy_bits(password):
    """log2(charset_size ** length) -- assumes uniform independent chars."""
    if not password:
        return 0.0
    size = charset_size(password)
    if size == 0:
        return 0.0
    return len(password) * math.log2(size)


def has_repeats(password):
    return bool(_REPEAT_RE.search(password))


def has_sequential_run(password, run_len=3):
    lowered = password.lower()
    for i in range(len(lowered) - run_len + 1):
        chunk = lowered[i:i + run_len]
        if chunk in _SEQUENCES or chunk[::-1] in _SEQUENCES:
            return True
    return False


def classify_strength(password):
    """
    Returns (label, score) where label is one of
    "None" / "Weak" / "Medium" / "Strong" and score is 0-100.
    """
    if not password:
        return "None", 0

    bits = estimate_entropy_bits(password)

    penalties = 0
    if has_repeats(password):
        penalties += 1
    if has_sequential_run(password):
        penalties += 1
    if len(set(password.lower())) < max(1, len(password) * 0.5):
        penalties += 1

    # 128 bits treated as a practical "full score" ceiling for the meter.
    raw_score = (bits / 128) * 100
    score = int(max(0, min(100, raw_score - penalties * 10)))

    if bits < 35 or penalties >= 2:
        label = "Weak"
    elif bits < 60:
        label = "Medium"
    else:
        label = "Strong"

    return label, score
