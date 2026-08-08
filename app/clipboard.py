"""
clipboard.py
Clipboard convenience wrapper with best-effort auto-clear.

LIMITATION: Clipboard clearing is best-effort only. Clipboard managers,
sync services (e.g. cloud clipboard history), and other applications may
have already read or cached the value before the timer fires. Do not
treat auto-clear as a strong security guarantee.
"""

import threading

try:
    import pyperclip
    _AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the dep installed
    _AVAILABLE = False

_clear_timer = None


def is_available():
    return _AVAILABLE


def copy_to_clipboard(text, clear_after_seconds=30):
    """Copy `text` to the system clipboard and schedule a best-effort clear."""
    global _clear_timer
    if not _AVAILABLE:
        raise RuntimeError("pyperclip is not installed or no clipboard backend is available.")

    pyperclip.copy(text)

    if _clear_timer is not None:
        _clear_timer.cancel()

    if clear_after_seconds:
        _clear_timer = threading.Timer(clear_after_seconds, _clear_if_unchanged, args=(text,))
        _clear_timer.daemon = True
        _clear_timer.start()


def _clear_if_unchanged(expected_text):
    """Only clear if the clipboard still holds what we put there."""
    try:
        if pyperclip.paste() == expected_text:
            pyperclip.copy("")
    except Exception:
        pass


def clear_clipboard():
    global _clear_timer
    if _clear_timer is not None:
        _clear_timer.cancel()
        _clear_timer = None
    if _AVAILABLE:
        try:
            pyperclip.copy("")
        except Exception:
            pass
