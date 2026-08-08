import unittest

from app.strength import (
    charset_size,
    classify_strength,
    estimate_entropy_bits,
    has_repeats,
    has_sequential_run,
)


class TestCharsetSize(unittest.TestCase):
    def test_lower_only(self):
        self.assertEqual(charset_size("abc"), 26)

    def test_mixed(self):
        self.assertEqual(charset_size("Ab1!"), 26 + 26 + 10 + 32)

    def test_empty(self):
        self.assertEqual(charset_size(""), 0)


class TestEntropy(unittest.TestCase):
    def test_empty_password(self):
        self.assertEqual(estimate_entropy_bits(""), 0.0)

    def test_longer_password_has_more_entropy(self):
        short = estimate_entropy_bits("abcDEF12")
        long = estimate_entropy_bits("abcDEF12abcDEF12")
        self.assertGreater(long, short)

    def test_more_charset_diversity_increases_entropy(self):
        letters_only = estimate_entropy_bits("abcdefgh")
        mixed = estimate_entropy_bits("abcdEF1!")
        self.assertGreater(mixed, letters_only)


class TestPatternDetection(unittest.TestCase):
    def test_has_repeats_true(self):
        self.assertTrue(has_repeats("aaabbb"))

    def test_has_repeats_false(self):
        self.assertFalse(has_repeats("abcdef"))

    def test_sequential_forward(self):
        self.assertTrue(has_sequential_run("xy123z"))

    def test_sequential_none(self):
        self.assertFalse(has_sequential_run("qz7kd9"))


class TestClassifyStrength(unittest.TestCase):
    def test_empty_is_none(self):
        label, score = classify_strength("")
        self.assertEqual(label, "None")
        self.assertEqual(score, 0)

    def test_low_entropy_password_is_weak(self):
        # classify_strength is a pure entropy/pattern heuristic -- it does
        # NOT check a common-password list (see analyzer.py for that).
        label, _ = classify_strength("aaaa1111")
        self.assertEqual(label, "Weak")

    def test_long_diverse_password_is_strong(self):
        label, score = classify_strength("qX9!zT4$wR7@pL2#")
        self.assertEqual(label, "Strong")
        self.assertGreater(score, 60)

    def test_score_within_bounds(self):
        for pwd in ["a", "aaaaaaaaaaaa", "Zx9!qW8@eR7#", "password123"]:
            _, score = classify_strength(pwd)
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)


if __name__ == "__main__":
    unittest.main()
