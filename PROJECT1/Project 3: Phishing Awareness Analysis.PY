import re

# ------------------------------
# PHISHING AWARENESS ANALYZER
# ------------------------------

def phishing_scan(email):

    score = 0
    report = []

    text = email.lower()

    # 1. Suspicious Keywords
    keywords = [
        "urgent", "verify", "password", "login",
        "otp", "bank", "account", "click",
        "reward", "winner", "limited",
        "security", "immediately",
        "confidential", "update"
    ]

    found = []

    for word in keywords:
        if word in text:
            found.append(word)

    if found:
        score += len(found)
        report.append("Suspicious keywords found: " + ", ".join(found))

    # 2. URL Detection
    urls = re.findall(r'https?://\S+|www\.\S+', email)

    if urls:
        score += 2
        report.append("Contains URL(s): " + ", ".join(urls))

        for url in urls:

            if "-" in url:
                score += 1
                report.append("URL contains unusual hyphen (-).")

            if "@" in url:
                score += 2
                report.append("URL contains '@' symbol.")

            if url.count(".") >= 3:
                score += 1
                report.append("Complex sub-domain detected.")

    # 3. Email Address Check
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', email)

    for e in emails:

        domain = e.split("@")[1]

        free_domains = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com"
        ]

        if domain in free_domains:
            score += 2
            report.append(f"Uses free email provider ({domain}).")

    # 4. Urgency Detection
    urgent_words = [
        "immediately",
        "act now",
        "within 24 hours",
        "expire",
        "urgent"
    ]

    for u in urgent_words:
        if u in text:
            score += 1
            report.append("Creates unnecessary urgency.")

    # 5. Sensitive Information Request
    sensitive = [
        "password",
        "otp",
        "credit card",
        "bank account",
        "cvv"
    ]

    for item in sensitive:
        if item in text:
            score += 2
            report.append(f"Requests sensitive information ({item}).")

    # 6. Excessive Capital Letters
    upper = sum(ch.isupper() for ch in email)

    if upper > len(email) * 0.30:
        score += 1
        report.append("Too many capital letters used.")

    # 7. Multiple Exclamation Marks
    if email.count("!") >= 3:
        score += 1
        report.append("Excessive exclamation marks detected.")

    # Final Result
    if score >= 10:
        status = "HIGH RISK PHISHING"
    elif score >= 5:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return status, report


print("=" * 65)
print("         PHISHING AWARENESS ANALYSIS SYSTEM")
print("=" * 65)

message = input("\nPaste Email or Message:\n\n")

result, details = phishing_scan(message)

print("\n" + "=" * 65)
print("ANALYSIS REPORT")
print("=" * 65)

print("Risk Level :", result)

print("\nRed Flags Found:")

if details:
    for i, item in enumerate(details, 1):
        print(f"{i}. {item}")
else:
    print("No suspicious indicators found.")

print("\nExplanation:")

if result == "SAFE":
    print("The message appears safe based on the current analysis.")
elif result == "SUSPICIOUS":
    print("This message contains multiple warning signs. Verify the sender before taking any action.")
else:
    print("This message strongly resembles a phishing attack. Do not click links, open attachments, or share personal information.")