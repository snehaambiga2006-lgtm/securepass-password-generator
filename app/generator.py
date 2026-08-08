"""
generator.py
Cryptographically secure password and passphrase generation.

All randomness comes from `secrets`, which is backed by the OS CSPRNG.
`random` is never used anywhere in this module.
"""

import secrets
import string

AMBIGUOUS_CHARS = "0Ol1I|"

DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"

# Small, dependency-free word list for passphrases (EFF-style short words).
# Not exhaustive by design -- entropy comes from word COUNT, not list size
# being enormous; a 7776-word list is ideal for real-world use, this is a
# compact stand-in so the project has zero external data files.
WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actual", "adapt",
    "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
    "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha",
    "already", "also", "alter", "always", "amazing", "among", "amount", "amused",
    "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle",
    "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any",
    "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armor", "army", "around", "arrange",
    "arrest", "arrive", "arrow", "art", "artist", "artwork", "aspect", "assault",
    "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend",
    "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto",
    "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag",
    "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely",
    "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean",
    "beauty", "because", "become", "beef", "before", "begin", "behave", "behind",
    "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird",
    "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
    "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush",
    "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book",
    "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box",
    "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
    "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken",
    "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget",
    "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden",
    "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
]


class GeneratorError(ValueError):
    """Raised for invalid generator configuration or input."""


def _build_pools(use_upper, use_lower, use_digits, use_symbols,
                  custom_symbols, exclude_ambiguous):
    pools = {}
    if use_lower:
        pools["lower"] = string.ascii_lowercase
    if use_upper:
        pools["upper"] = string.ascii_uppercase
    if use_digits:
        pools["digits"] = string.digits
    if use_symbols:
        pools["symbols"] = custom_symbols if custom_symbols else DEFAULT_SYMBOLS

    if exclude_ambiguous:
        pools = {
            name: "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
            for name, chars in pools.items()
        }

    # Drop any pool that became empty (e.g. custom_symbols was only ambiguous chars)
    pools = {name: chars for name, chars in pools.items() if chars}
    return pools


def generate_password(
    length=16,
    use_upper=True,
    use_lower=True,
    use_digits=True,
    use_symbols=True,
    exclude_ambiguous=False,
    custom_symbols=None,
    min_per_type=1,
):
    """
    Generate a cryptographically secure random password.

    Guarantees:
      - Every selected character type contributes at least `min_per_type`
        characters (checked, not just probabilistically likely).
      - Character selection AND final ordering both use `secrets`.

    Raises GeneratorError on invalid configuration.
    """
    if not isinstance(length, int) or not (8 <= length <= 128):
        raise GeneratorError("Password length must be an integer between 8 and 128.")

    pools = _build_pools(use_upper, use_lower, use_digits, use_symbols,
                          custom_symbols, exclude_ambiguous)

    if len(pools) < 2:
        raise GeneratorError("Select at least two character types.")

    if length < len(pools) * min_per_type:
        raise GeneratorError(
            f"Length {length} is too short to guarantee {min_per_type} "
            f"character(s) from each of {len(pools)} selected types."
        )

    all_chars = "".join(pools.values())

    # 1) Guarantee minimum representation per type.
    chars = []
    for pool in pools.values():
        for _ in range(min_per_type):
            chars.append(secrets.choice(pool))

    # 2) Fill the rest from the combined pool.
    while len(chars) < length:
        chars.append(secrets.choice(all_chars))

    # 3) Secure Fisher-Yates shuffle (do NOT use random.shuffle).
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def generate_passphrase(
    word_count=4,
    separator="-",
    capitalize=False,
    include_number=False,
    wordlist=None,
):
    """
    Generate a Diceware-style passphrase using `secrets.choice`.

    Note: real-world entropy depends on wordlist size. This project's
    built-in list is intentionally compact for a zero-dependency demo;
    swap in a full 7776-word EFF list for production use.
    """
    if not isinstance(word_count, int) or word_count < 2:
        raise GeneratorError("Passphrase needs at least 2 words.")

    source = wordlist if wordlist else WORDLIST
    words = [secrets.choice(source) for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    if include_number:
        idx = secrets.randbelow(len(words))
        words[idx] = f"{words[idx]}{secrets.randbelow(100)}"

    return separator.join(words)


PRESETS = {
    "Basic":   dict(length=12, use_upper=True,  use_lower=True, use_digits=True,
                     use_symbols=False, exclude_ambiguous=False),
    "Strong":  dict(length=16, use_upper=True,  use_lower=True, use_digits=True,
                     use_symbols=True,  exclude_ambiguous=True),
    "Maximum": dict(length=24, use_upper=True,  use_lower=True, use_digits=True,
                     use_symbols=True,  exclude_ambiguous=True),
}
