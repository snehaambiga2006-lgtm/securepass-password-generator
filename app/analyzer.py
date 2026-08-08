"""
analyzer.py
Fully local, offline password analysis. The password passed to `analyze()`
is used only in-process for this single call -- it is never written to
disk, logged, or transmitted anywhere.
"""

import re
from .strength import estimate_entropy_bits, classify_strength, has_repeats, has_sequential_run

# Small local blocklist for demo purposes -- NOT a substitute for a real
# breach-corpus check (e.g. HaveIBeenPwned k-anonymity API), which is
# intentionally out of scope for this offline-only tool.
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "letmein", "admin",
    "welcome", "iloveyou", "monkey", "dragon", "abc123", "111111",
    "password1", "123456789", "football", "1234567", "sunshine",
}


def analyze(password):
    """Return a dict of local metrics + human-readable warnings."""
    if not password:
        return {"error": "Enter a password to analyze."}

    label, score = classify_strength(password)

    result = {
        "length": len(password),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "entropy_bits": round(estimate_entropy_bits(password), 1),
        "strength_label": label,
        "score": score,
        "has_repeats": has_repeats(password),
        "has_sequential": has_sequential_run(password),
        "is_common": password.lower() in COMMON_PASSWORDS,
        "unique_chars": len(set(password)),
    }

    warnings = []
    if result["length"] < 12:
        warnings.append("Consider using at least 12 characters.")
    if result["is_common"]:
        warnings.append("This exact password is a widely known common password.")
    if result["has_repeats"]:
        warnings.append("Contains 3+ repeated characters in a row.")
    if result["has_sequential"]:
        warnings.append("Contains a sequential run (e.g. abc, 123).")
    if result["unique_chars"] < max(1, result["length"] * 0.5):
        warnings.append("Low character diversity relative to length.")
    if not (result["has_upper"] and result["has_lower"] and
             result["has_digit"] and result["has_symbol"]):
        warnings.append("Mixing all four character types increases entropy.")

    result["warnings"] = warnings
    return result
