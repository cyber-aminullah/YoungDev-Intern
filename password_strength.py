import re

def password_strength(password):
    # Check length
    if len(password) < 8:
        return "Weak: Password should be at least 8 characters long."

    # Check for uppercase, lowercase, and digits
    if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password):
        return "Weak: Password should include uppercase and lowercase letters, and digits."

    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Weak: Password should include at least one special character."

    return "Strong: Password meets all criteria."

if __name__ == "__main__":
    user_password = input("Enter your password: ")
    result = password_strength(user_password)
    print(result)
