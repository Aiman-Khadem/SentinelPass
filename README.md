# SentinelPass v2.0 - Password Strength Checker

**Developer:** Aiman Mansor Khadem Ahmed
**Programming Language:** Python

## Project Overview
SentinelPass is a professional security tool developed to evaluate password safety and raise cybersecurity awareness. While the initial version focused on length and character variety, the updated **v2.0** now includes **real-time breach detection** using the **HaveIBeenPwned API**.

## Key Features
* **Shannon Entropy Calculation:** Measures the mathematical unpredictability of a password.
* **Real-time Leak Check:** Connects to global databases to check if a password has been exposed in a data breach.
* **Pattern Detection:** Analyzes complexity using Regular Expressions (Regex).
* **User Feedback:** Provides clear, actionable advice to improve security.

## What I Learned
Through this project, I demonstrated how to translate complex security principles—like **K-Anonymity** for API privacy and mathematical entropy—into a practical tool. This development reflects my commitment to building proactive defense mechanisms and understanding digital infrastructure.

## How to Run
1. Ensure you have Python installed.
2. Install the required library: `pip install requests`
3. Run the script: `python sentinel_pass.py`
