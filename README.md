# Password Safety Checker

A small Python command-line tool that tells you whether a password has appeared in known data breaches and gives simple tips to make it stronger.

## What it does

1. Asks for a password using `getpass` (nothing is shown on screen).
2. Hashes it with SHA-1 on your own computer.
3. Sends **only the first 5 characters** of the hash to the [Have I Been Pwned Pwned Passwords range API](https://haveibeenpwned.com/API/v3#PwnedPasswords).
4. Compares the returned list against the rest of the hash **locally**.
5. Reports how many times the password appeared in breaches (or that it wasn't found).
6. Runs a simple strength check (length, uppercase, lowercase, digits, symbols) and lists what to improve.

## Why I built it

I wanted a practical project that shows real security ideas: hashing, k-anonymity, safe handling of secrets, and error handling when talking to a web API. The password itself never leaves my computer, and neither does the full hash.

## Install and run

Requires Python 3.8+.

```bash
pip install requests
python password_checker.py
```

`hashlib` and `getpass` are part of Python's standard library, so only `requests` needs installing.

## Sample output

```
Enter a password to check (hidden):

--- Breach check ---
DANGER: found 10,000,000+ times in known breaches. Do not use it!

--- Strength check ---
Checks passed: 3/5
- Use at least 12 characters.
- Add a symbol (e.g. ! @ # $ %).
```

(The exact count depends on the live database.)

## Limitations

- Needs an internet connection for the breach check.
- The strength check is a simple rule-based check. It does not detect common patterns like `Password123!`, keyboard walks (`qwerty`), or dictionary words, so a password can pass all 5 checks and still be weak.
- "Not found" does not mean "safe". It only means the password isn't in the known breach data.
- SHA-1 is used only because the API requires it. It is not suitable for storing passwords.
- Checks one password per run.

## Ideas for improvement

- Add a simple GUI (for example with Tkinter).
- Check a whole file of passwords and print a summary report.
- Add a secure password generator using the `secrets` module.
- Detect common patterns and dictionary words in the strength check.
- Add unit tests with a mocked API response.