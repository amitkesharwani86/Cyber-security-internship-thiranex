import re
import random
import string
import hashlib

# Store old password hashes
old_passwords = set()


# Hash password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Check if password was used before
def is_reused(password):
    return hash_password(password) in old_passwords


# Save password hash
def save_password(password):
    old_passwords.add(hash_password(password))


# Analyze password strength
def analyze_password(password):
    score = 0
    feedback = []

    # Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Increase password length to at least 12 characters.")

    # Uppercase Check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Lowercase Check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Number Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Special Character Check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 2
    else:
        feedback.append("Add special characters.")

    # Password Reuse Check
    if is_reused(password):
        feedback.append("Password has been used before.")
        score -= 2

    # Strength Rating
    if score <= 2:
        strength = "Weak"
    elif score <= 5:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, score, feedback


# Generate strong password suggestion
def generate_strong_password(length=16):
    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*"
    )

    password = ''.join(random.choice(characters) for _ in range(length))
    return password


# Main Program
def main():
    print("=" * 50)
    print("PASSWORD STRENGTH ANALYZER")
    print("=" * 50)

    while True:
        password = input("\nEnter Password: ")

        strength, score, feedback = analyze_password(password)

        print("\nPassword Analysis")
        print("-" * 30)
        print(f"Strength : {strength}")
        print(f"Score    : {score}/7")

        if feedback:
            print("\nSuggestions:")
            for item in feedback:
                print("•", item)

        if strength != "Strong":
            print("\nSuggested Strong Password:")
            print(generate_strong_password())

        save_choice = input("\nSave this password? (y/n): ").lower()

        if save_choice == 'y':
            save_password(password)
            print("Password hash stored successfully.")

        again = input("\nAnalyze another password? (y/n): ").lower()

        if again != 'y':
            print("\nThank you for using Password Strength Analyzer!")
            break


if __name__ == "__main__":
    main()