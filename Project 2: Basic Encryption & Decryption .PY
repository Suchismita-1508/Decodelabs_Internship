def encryption(message, key, mode):
    output = ""

    if mode == "decrypt":
        key = -key

    for ch in message:

        if ch.isalpha():

            base = ord('A') if ch.isupper() else ord('a')

            shifted = (ord(ch) - base + key) % 26

            output += chr(base + shifted)

        else:
            output += ch

    return output


print("=" * 50)
print("      BASIC ENCRYPTION & DECRYPTION SYSTEM")
print("=" * 50)

text = input("Enter your message: ")

while True:
    try:
        shift = int(input("Enter shift key (1-25): "))
        if 1 <= shift <= 25:
            break
        print("Shift key must be between 1 and 25.")
    except ValueError:
        print("Please enter a valid integer.")

encrypted = encryption(text, shift, "encrypt")
decrypted = encryption(encrypted, shift, "decrypt")

print("\nOriginal Message : ", text)
print("Encrypted Text  : ", encrypted)
print("Decrypted Text  : ", decrypted)

if text == decrypted:
    print("\nVerification: Decryption Successful")
else:
    print("\nVerification: Error in Encryption/Decryption")