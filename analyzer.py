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
    [span_2](start_span)[span_3](start_span)Calculates Shannon Entropy to measure password unpredictability[span_2](end_span)[span_3](end_span).
    Formula: H = L * log2(N)
    """
    pool_size = 0
    # [span_4](start_span)Check for lowercase letters[span_4](end_span)
    if re.search(r'[a-z]', password): pool_size += 26
    # [span_5](start_span)[span_6](start_span)Check for uppercase letters[span_5](end_span)[span_6](end_span)
    if re.search(r'[A-Z]', password): pool_size += 26
    # [span_7](start_span)[span_8](start_span)Check for numbers[span_7](end_span)[span_8](end_span)
    if re.search(r'[0-9]', password): pool_size += 10
    # [span_9](start_span)[span_10](start_span)Check for special characters[span_9](end_span)[span_10](end_span)
    if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32

    if pool_size == 0:
        return 0

    [span_11](start_span)[span_12](start_span)entropy = len(password) * math.log2(pool_size)[span_11](end_span)[span_12](end_span)
    return round(entropy, 2)

def check_pwned_api(password):
    """
    [span_13](start_span)Checks if the password has appeared in known data breaches[span_13](end_span).
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
    [span_14](start_span)[span_15](start_span)Analyzes password based on length, complexity, and entropy[span_14](end_span)[span_15](end_span).
    """
    score = 0
    feedback = []

    # [span_16](start_span)[span_17](start_span)Check Length[span_16](end_span)[span_17](end_span)
    if len(password) < 8:
        feedback.append("[-] Password is too short (min 8 chars).")
    else:
        score += 1
        feedback.append("[+] Good length.")

    # [span_18](start_span)[span_19](start_span)Check Complexity using Regular Expressions[span_18](end_span)[span_19](end_span)
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("[-] Add uppercase letters (A-Z).")

    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("[-] Add numbers (0-9).")

    if re.search(r"[!@#$%^&*]", password): score += 1
    else: feedback.append("[-] Add special characters (!@#$%).")

    # [span_20](start_span)Get Entropy score and Breach status[span_20](end_span)
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
