import os
import re
import math
import random
import string
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# List of common weak passwords to flag
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "1234", "qwerty", "1234567890", "111111", "admin", "welcome",
    "password123", "pass123", "iloveyou", "sunshine", "secret",
    "monkey", "dragon", "master", "login", "abc123456", "p@ssword",
    "p@ssw0rd", "admin123", "guest", "letmein"
}


def calculate_entropy(password):
    """Calculate password entropy in bits."""
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[^A-Za-z0-9]', password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


def estimate_crack_time(entropy):
    """Estimate time required to crack password given its entropy."""
    if entropy <= 0:
        return "Instant"

    # Assume 10 billion (10^10) attempts per second (modern GPU cracking rate)
    guesses = 2 ** (entropy - 1)
    seconds = guesses / 10_000_000_000

    if seconds < 1:
        return "Instant"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    elif seconds < 31536000 * 100:
        return f"{int(seconds / 31536000)} years"
    elif seconds < 31536000 * 1_000_000:
        return f"{int(seconds / (31536000 * 1000))} thousand years"
    else:
        return "Centuries+"


def evaluate_password(password):
    """Evaluate password and return detailed analysis."""
    if not password:
        return {
            "password": "",
            "score": 0,
            "level": "None",
            "label": "Enter a password",
            "entropy": 0,
            "crack_time": "Instant",
            "checks": {
                "length": False,
                "length_strong": False,
                "uppercase": False,
                "lowercase": False,
                "number": False,
                "special": False,
            },
            "suggestions": ["Type a password to check its strength."],
            "is_common": False
        }

    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_number = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))

    checks = {
        "length": length >= 8,
        "length_strong": length >= 12,
        "uppercase": has_upper,
        "lowercase": has_lower,
        "number": has_number,
        "special": has_special,
    }

    is_common = password.lower() in COMMON_PASSWORDS

    # Score calculation (0 - 100 scale)
    score = 0

    # Length points (up to 40)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    elif length >= 5:
        score += 10
    else:
        score += 5

    # Character variety points (up to 40)
    variety_count = sum([has_upper, has_lower, has_number, has_special])
    score += variety_count * 10

    # Extra bonus points (up to 20)
    # Check for mixed character types with good length
    if length >= 10 and variety_count >= 3:
        score += 10
    if length >= 14 and variety_count == 4:
        score += 10

    # Deductions for weak practices
    if is_common:
        score = max(5, score - 50)

    # Check for sequential patterns (e.g. 123, abc, qwerty)
    if re.search(r'(?:123|234|345|456|567|678|789|abc|bcd|cde|def|qwerty|asdf)', password.lower()):
        score = max(5, score - 15)

    # Check for repeated characters (e.g., aaa, 111)
    if re.search(r'(.)\1{2,}', password):
        score = max(5, score - 10)

    # Cap score at 100
    score = min(100, max(0, score))

    # Determine Strength Level
    if is_common or score < 30:
        level = "Weak"
    elif score < 70:
        level = "Medium"
    else:
        level = "Strong"

    # Detailed label
    if is_common:
        label = "Weak (Common Password)"
    elif score < 30:
        label = "Weak"
    elif score < 50:
        label = "Fair"
    elif score < 70:
        label = "Medium"
    elif score < 90:
        label = "Strong"
    else:
        label = "Very Strong"

    # Entropy & Crack Time
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    # Generate helpful actionable suggestions
    suggestions = []

    if is_common:
        suggestions.append("⚠️ This is a commonly used password. Avoid using frequent words or simple patterns.")
    
    if not checks["length"]:
        suggestions.append("Increase password length to at least 8 characters (12+ recommended).")
    elif not checks["length_strong"]:
        suggestions.append("Make it even stronger by extending length to 12 or more characters.")

    if not checks["uppercase"]:
        suggestions.append("Add at least one uppercase letter (A-Z).")

    if not checks["lowercase"]:
        suggestions.append("Add at least one lowercase letter (a-z).")

    if not checks["number"]:
        suggestions.append("Include at least one number (0-9).")

    if not checks["special"]:
        suggestions.append("Include at least one special character (e.g. !@#$%^&*).")

    if re.search(r'(.)\1{2,}', password):
        suggestions.append("Avoid repeating the same character 3 or more times consecutively.")

    if re.search(r'(?:123|234|345|456|567|678|789|abc|bcd|qwerty)', password.lower()):
        suggestions.append("Avoid sequential keyboard combinations like '123' or 'qwerty'.")

    if not suggestions:
        suggestions.append("Great job! Your password meets all standard security recommendations.")

    return {
        "password": password,
        "score": score,
        "level": level,
        "label": label,
        "entropy": entropy,
        "crack_time": crack_time,
        "checks": checks,
        "suggestions": suggestions,
        "is_common": is_common
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check-password", methods=["POST"])
def check_password_api():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    result = evaluate_password(password)
    return jsonify(result)


@app.route("/api/generate-password", methods=["POST"])
def generate_password_api():
    data = request.get_json(silent=True) or {}
    length = int(data.get("length", 16))
    length = max(8, min(64, length))

    use_upper = data.get("uppercase", True)
    use_lower = data.get("lowercase", True)
    use_numbers = data.get("numbers", True)
    use_symbols = data.get("symbols", True)

    char_pools = []
    guaranteed = []

    if use_lower:
        char_pools.append(string.ascii_lowercase)
        guaranteed.append(random.choice(string.ascii_lowercase))
    if use_upper:
        char_pools.append(string.ascii_uppercase)
        guaranteed.append(random.choice(string.ascii_uppercase))
    if use_numbers:
        char_pools.append(string.digits)
        guaranteed.append(random.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        char_pools.append(symbols)
        guaranteed.append(random.choice(symbols))

    if not char_pools:
        # Default fallback
        char_pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
        guaranteed = [random.choice(p) for p in char_pools]

    all_chars = "".join(char_pools)
    remaining_length = length - len(guaranteed)
    
    random_chars = [random.choice(all_chars) for _ in range(remaining_length)]
    combined = guaranteed + random_chars
    random.shuffle(combined)
    
    generated_password = "".join(combined)
    
    # Return password along with its evaluation
    analysis = evaluate_password(generated_password)
    return jsonify({
        "generated_password": generated_password,
        "analysis": analysis
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
