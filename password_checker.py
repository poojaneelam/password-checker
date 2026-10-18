"""Password Safety Checker: breach check (k-anonymity) + simple strength check."""
import hashlib   # to turn the password into a SHA-1 hash
import getpass   # to read the password without showing it on screen
import requests  # to talk to the Have I Been Pwned (HIBP) API

API_URL = "https://api.pwnedpasswords.com/range/"  # API address; we add the 5-char prefix
TIMEOUT = 10  # seconds to wait, so the program never hangs forever


def hash_password(password):
    """Return the SHA-1 hash of the password as an UPPERCASE hex string."""
    # encode() converts text to bytes, because hashlib only accepts bytes
    data = password.encode("utf-8")
    # hexdigest() gives readable hex; upper() matches the format the API uses
    return hashlib.sha1(data).hexdigest().upper()


def check_breach(password):
    """Return how many times the password appears in known breaches (0 = not found)."""
    full_hash = hash_password(password)  # 40-character hash of the password
    prefix, suffix = full_hash[:5], full_hash[5:]  # only the prefix will leave this computer
    # Send ONLY the prefix (k-anonymity); timeout stops us waiting forever
    response = requests.get(API_URL + prefix, timeout=TIMEOUT)
    response.raise_for_status()  # turn HTTP errors (404, 500...) into exceptions
    count = 0  # stays 0 if our suffix is not in the list
    for line in response.text.splitlines():  # each line looks like SUFFIX:COUNT
        parts = line.split(":")  # separate the hash suffix from the count
        if len(parts) != 2 or not parts[1].strip().isdigit():
            raise ValueError("Unexpected data format from the API")  # bad response
        if parts[0] == suffix:  # the comparison happens locally, on our machine
            count = int(parts[1])  # how many times this password was leaked
    return count


def check_strength(password):
    """Return a list of tips describing what is missing from the password."""
    tips = []  # we collect improvement tips here
    if len(password) < 12:  # short passwords are easier to brute-force
        tips.append("Use at least 12 characters.")
    if not any(c.isupper() for c in password):  # more character types = more combinations
        tips.append("Add an uppercase letter (A-Z).")
    if not any(c.islower() for c in password):
        tips.append("Add a lowercase letter (a-z).")
    if not any(c.isdigit() for c in password):
        tips.append("Add a digit (0-9).")
    if not any(not c.isalnum() for c in password):  # not a letter/digit = symbol
        tips.append("Add a symbol (e.g. ! @ # $ %).")
    return tips

def ask_password():
    """Ask if the user wants to see the password while typing, then read it."""
    # input() is fine here because this is only a yes/no question, not a secret
    choice = input("Show password while typing? (y/N): ").strip().lower()
    if choice == "y":  # only show it if the user clearly opted in
        return input("Enter a password to check (visible): ")  # input() echoes on screen
    # anything else (including just pressing Enter) stays hidden, the safe default
    return getpass.getpass("Enter a password to check (hidden): ")


def main():
    """Ask for a password, run both checks, and print the results."""
    password = ask_password()  # lets the user choose visible or hidden input  # hidden input
    if not password:  # an empty password can't be checked meaningfully
        print("No password entered.")
        return

    print("\n--- Breach check ---")
    try:
        count = check_breach(password)
        if count > 0:
            print(f"DANGER: found {count:,} times in known breaches. Do not use it!")
        else:
            print("Good news: not found in known breaches.")
    except requests.exceptions.ConnectionError:  # no internet / DNS failure
        print("Error: could not connect. Check your internet connection.")
    except requests.exceptions.Timeout:  # server too slow
        print("Error: the request timed out. Try again later.")
    except requests.exceptions.HTTPError as e:  # server replied with an error code
        print(f"Error: the API returned an error ({e}).")
    except ValueError:  # our format check failed
        print("Error: the API sent a response we couldn't understand.")

    print("\n--- Strength check ---")
    tips = check_strength(password)
    print(f"Checks passed: {5 - len(tips)}/5")  # 5 checks in total
    for tip in tips:  # show only what needs improving
        print(f"- {tip}")


if __name__ == "__main__":  # run main() only when executed directly, not when imported
    main()