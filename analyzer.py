# Project Title: SentinelPass - Password Strength Checker
# Developer: Aiman Mansor Khadem Ahmed
# Programming Language: Python
# Description: A tool to evaluate password safety using Shannon Entropy and real-time leak detection.

import re
import math
import hashlib
import requests

def calculate_entropy(password):
    """
    Calculates Shannon Entropy to measure password unpredictability.
    Formula: H = L * log2(N)
    """
    pool_size = 0
    # Check for lowercase letters
    if re.search(r'[a-z]', password): pool_size += 26
    # Check for uppercase letters
    if re.search(r'[A-Z]', password): pool_size += 26
    # Check for numbers
    if re.search(r'[0-9]', password): pool_size += 10
    # Check for special characters
    if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32

    if pool_size == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def check_pwned_api(password):
    """
    Checks if the password has appeared in known data breaches.
    Uses the HaveIBeenPwned API via K-Anonymity for privacy.
    """
    # Create SHA-1 hash of the password
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1_password[:5], sha1_password[5:]
    
    url = f'https://api.pwnedpasswords.com/range/{first5}'
    try:
        res = requests.get(url)
        if res.status_code != 200:
            return "Unable to check leaks (System Busy)"

        # Search for the tail of the hash in the results
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == tail:
                return f"⚠️ EXPOSED! Found in {count} data leaks."
        return "✅ Safe: Not found in known leaks."
    except:
        return "Connection error (Check your internet)"

def check_password_strength(password):
    """
    Analyzes password based on length, complexity, and entropy.
    """
    score = 0
    feedback = []

    # Check Length
    if len(password) < 8:
        feedback.append("[-] Password is too short (min 8 chars).")
    else:
        score += 1
        feedback.append("[+] Good length.")

    # Check Complexity using Regular Expressions
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("[-] Add uppercase letters (A-Z).")

    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("[-] Add numbers (0-9).")

    if re.search(r"[!@#$%^&*]", password): score += 1
    else: feedback.append("[-] Add special characters (!@#$%).")

    # Get Entropy score and Breach status
    entropy = calculate_entropy(password)
    leak_status = check_pwned_api(password)

    print(f"\n--- Analysis Report for: {password} ---")
    print(f"Entropy Score: {entropy} bits")
    print(f"Breach Status: {leak_status}")

    # Final Security Decision
    if entropy < 40 or "EXPOSED" in leak_status:
        print(">> Result: WEAK 🔴 (High Risk)")
    elif entropy < 60:
        print(">> Result: MODERATE 🟡")
    else:
        print(">> Result: STRONG 🟢 (High Resistance)")

    print("\nDetails:")
    for item in feedback:
        print(item)

if __name__ == "__main__":
    print("Welcome to SentinelPass v2.0")
    print("Developed by Aiman Mansor Khadem Ahmed")
    print("Type 'exit' to quit.")

    while True:
        user_pass = input("\nEnter password to analyze: ")
        if user_pass.lower() == 'exit':
            break
        check_password_strength(user_pass)
