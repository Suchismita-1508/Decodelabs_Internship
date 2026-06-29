import string

def check_password_strength(password):
    score = 0
    remarks = []

    # Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        remarks.append("Password should contain at least 8 characters.")

    # Character Checks
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(ch in string.punctuation for ch in password)

    if has_upper:
        score += 1
    else:
        remarks.append("Include at least one uppercase letter.")

    if has_lower:
        score += 1
    else:
        remarks.append("Include at least one lowercase letter.")

    if has_digit:
        score += 1
    else:
        remarks.append("Include at least one number.")

    if has_symbol:
        score += 1
    else:
        remarks.append("Include at least one special character.")

    # Strength Decision
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, remarks


print("=" * 45)
print("      PASSWORD STRENGTH CHECKER")
print("=" * 45)

password = input("Enter your password: ")

strength, suggestions = check_password_strength(password)

print("\nPassword Strength:", strength)

if suggestions:
    print("\nSuggestions to Improve:")
    for item in suggestions:
        print("-", item)
else:
    print("\nExcellent! Your password follows all recommended security practices.")