# 🔐 SecurePass

A local, offline desktop password & passphrase generator with a strength/entropy
analyzer, built with Python and Tkinter. No network calls, no database, no
persisted secrets — everything happens in memory on your machine.

## Overview

SecurePass generates cryptographically secure random passwords and Diceware-style
passphrases, estimates their strength/entropy, and offers a local analyzer for
passwords you type in. It's built as a small, readable reference project — every
module has a single responsibility and no external services are involved.

## Features

- Configurable password length (8–128)
- Toggle uppercase / lowercase / digits / symbols, with a minimum of two types required
- Guarantees at least one character from every selected type (not just probable — checked)
- All randomness from Python's `secrets` module (CSPRNG-backed), never `random`
- Optional exclusion of visually ambiguous characters (`0 O l 1 I`)
- Show/hide password toggle
- Weak / Medium / Strong strength classification with a visual meter
- Approximate Shannon entropy estimate (bits)
- Auto-copy to clipboard + manual Copy button
- Best-effort clipboard auto-clear (see [Security Design](#security-design) for limits)
- Session-only history of the last 5 generated values (never written to disk)
- Passphrase generator: word count, separator, capitalization, optional number
- Custom symbol sets and generation presets (Basic / Strong / Maximum / Custom)
- Fully local password analyzer (checks length, composition, repeats, sequences,
  common-password list, entropy)
- Security Lab tab: entropy, diversity, and score breakdown; session statistics
  that never expose plaintext
- Dark / light theme toggle
- Toast-style notifications
- Keyboard shortcuts (`Ctrl+G` generate, `Ctrl+Shift+C` copy)
- Resizable layout

## Screenshots

Add screenshots to `assets/screenshots/` and reference them here, e.g.:

```
![Generator tab](assets/screenshots/generator.png)
![Security Lab](assets/screenshots/security_lab.png)
```

## Technologies

- Python 3.9+
- Tkinter / ttk (standard library) — GUI
- `secrets`, `string` (standard library) — secure generation
- `pyperclip` — clipboard access
- `unittest` (standard library) — tests

## Installation

```bash
git clone https://github.com/<your-username>/SecurePass.git
cd SecurePass
```

### Virtual environment setup

```bash
python3 -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt
```

> **Note:** Tkinter ships with most Python installations. On some Linux
> distributions you may need to install it separately, e.g.
> `sudo apt install python3-tk`.

## Running

```bash
python main.py
```

## Testing

```bash
python -m unittest discover -s tests -v
```

All generator and strength-scoring logic is covered by unit tests in `tests/`.

## Architecture

```
SecurePass/
├── main.py                # Entry point — launches the GUI
├── app/
│   ├── generator.py        # secrets-based password & passphrase generation
│   ├── strength.py         # Entropy estimation & Weak/Medium/Strong scoring
│   ├── analyzer.py         # Local, offline analysis of a typed-in password
│   ├── clipboard.py        # Copy + best-effort auto-clear via pyperclip
│   ├── history.py          # In-memory-only session history (max 5 items)
│   └── gui.py               # Tkinter/ttk UI: tabs, theming, shortcuts, toasts
├── tests/
│   ├── test_generator.py
│   └── test_strength.py
├── assets/screenshots/
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

The GUI (`gui.py`) is a thin presentation layer — all generation, scoring, and
analysis logic lives in plain, GUI-independent modules under `app/`, so the
core logic can be unit tested (and reused, e.g. in a CLI) without touching Tkinter.

## Security Design

**What this project does:**
- Uses `secrets` (OS CSPRNG) for all random character/word selection — `random`
  is never used for anything security-relevant.
- Guarantees requested character-type composition deterministically, not just
  probabilistically.
- Generates and analyzes everything locally, in-process. No network requests
  are made anywhere in the codebase.
- Never writes generated passwords to disk, a database, or a log file.
- Keeps history capped at 5 items, in memory only, cleared on exit.

**Known limitations (please read before relying on this for real secrets):**
- **Strength score is a heuristic**, not a guarantee. It estimates entropy
  assuming a uniform random character distribution and penalizes obvious
  patterns (repeats, runs, low diversity). It does **not** model real-world
  attacker knowledge, dictionary attacks, or check breach corpora — a high
  score is not proof a password can't be cracked.
- **Clipboard clearing is best-effort.** OS clipboard managers, cloud clipboard
  sync, and other running applications may read or cache the clipboard value
  before the auto-clear timer fires. Don't assume the clipboard is guaranteed-empty.
- **The built-in analyzer's "common password" list is a small illustrative set**,
  not a real breach database. For production use, integrate a proper check
  (e.g. the HaveIBeenPwned k-anonymity API) — intentionally out of scope here
  to keep the tool 100% offline.
- **The passphrase word list is intentionally compact** (a few hundred words)
  to avoid bundling a large external data file. Real-world entropy from a
  Diceware-style passphrase depends heavily on word-list size; swap in the
  full 7,776-word EFF list for anything beyond a demo.
- This is a **generation and local-analysis tool only** — it does not manage,
  store, or sync your actual credentials. Use a dedicated password manager for that.

## Future Improvements

- Pluggable, larger Diceware word list (EFF long/short list)
- Optional integration with the HaveIBeenPwned k-anonymity breach-check API
- Export/import of generation presets
- Packaged binaries (PyInstaller) for Windows/macOS/Linux
- Automated UI tests (e.g. via `pytest` + a headless X server)
- Localization / i18n

## License

MIT — see [LICENSE](LICENSE).
