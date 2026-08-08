import string
import unittest

from app.generator import (
    GeneratorError,
    generate_password,
    generate_passphrase,
)


class TestGeneratePassword(unittest.TestCase):
    def test_default_length(self):
        pwd = generate_password()
        self.assertEqual(len(pwd), 16)

    def test_length_bounds(self):
        with self.assertRaises(GeneratorError):
            generate_password(length=7)
        with self.assertRaises(GeneratorError):
            generate_password(length=129)
        # boundaries are valid
        self.assertEqual(len(generate_password(length=8)), 8)
        self.assertEqual(len(generate_password(length=128)), 128)

    def test_requires_two_types(self):
        with self.assertRaises(GeneratorError):
            generate_password(use_upper=False, use_lower=True, use_digits=False, use_symbols=False)

    def test_guarantees_each_selected_type_present(self):
        for _ in range(50):
            pwd = generate_password(
                length=12, use_upper=True, use_lower=True,
                use_digits=True, use_symbols=True,
            )
            self.assertTrue(any(c in string.ascii_uppercase for c in pwd))
            self.assertTrue(any(c in string.ascii_lowercase for c in pwd))
            self.assertTrue(any(c in string.digits for c in pwd))
            self.assertTrue(any(c not in string.ascii_letters + string.digits for c in pwd))

    def test_exclude_ambiguous(self):
        ambiguous = set("0Ol1I|")
        for _ in range(50):
            pwd = generate_password(length=40, exclude_ambiguous=True)
            self.assertFalse(ambiguous.intersection(pwd))

    def test_custom_symbols_with_letters(self):
        for _ in range(20):
            pwd = generate_password(
                length=20, use_upper=False, use_lower=True, use_digits=False,
                use_symbols=True, custom_symbols="#$%",
            )
            symbol_chars = set(pwd) - set(string.ascii_lowercase)
            self.assertTrue(symbol_chars.issubset(set("#$%")))

    def test_randomness_not_identical(self):
        passwords = {generate_password() for _ in range(20)}
        self.assertGreater(len(passwords), 1)

    def test_invalid_length_type_raises(self):
        with self.assertRaises(GeneratorError):
            generate_password(length="16")


class TestGeneratePassphrase(unittest.TestCase):
    def test_word_count(self):
        phrase = generate_passphrase(word_count=5, separator="-")
        self.assertEqual(len(phrase.split("-")), 5)

    def test_minimum_word_count(self):
        with self.assertRaises(GeneratorError):
            generate_passphrase(word_count=1)

    def test_capitalize(self):
        phrase = generate_passphrase(word_count=4, capitalize=True, include_number=False)
        words = phrase.split("-")
        self.assertTrue(all(w[0].isupper() for w in words))

    def test_include_number(self):
        phrase = generate_passphrase(word_count=6, include_number=True)
        self.assertTrue(any(ch.isdigit() for ch in phrase))

    def test_custom_separator(self):
        phrase = generate_passphrase(word_count=3, separator="_")
        self.assertIn("_", phrase)


if __name__ == "__main__":
    unittest.main()
