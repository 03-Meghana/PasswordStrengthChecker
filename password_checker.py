from zxcvbn import zxcvbn
import getpass
from datetime import datetime

def analyze_password(password):
    result = zxcvbn(password)
    score = result['score']
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    feedback = result['feedback']['suggestions']
    patterns = [match['pattern'] for match in result['sequence']]
    return score, crack_time, feedback, patterns

def display_results(password, score, crack_time, feedback, patterns):
    print("\n📊 Password Analysis")
    print(f"Score: {score}/4")

    bar = "▮" * score + "▯" * (4 - score)
    print(f"Strength Meter: [{bar}]")

    risk_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    print(f"Risk Level: {risk_levels[score]}")
    print(f"Estimated Crack Time: {crack_time}")
    print(f"Detected Patterns: {', '.join(set(patterns)) if patterns else 'None'}")

    if "seconds" in crack_time or "minutes" in crack_time:
        print("⚠️ Your password could be cracked almost instantly !!")
    elif "hours" in crack_time or "days" in crack_time:
        print("⚠️ Your password is moderately secure but still vulnerable.")
    else:
        print("✅ Your password is highly secure against most attacks.")

    print("\n🔐 Tip: Avoid copying passwords into clipboard-based apps. Use a password manager instead.")

    print("\nSuggestions:")
    if feedback:
        for tip in feedback:
            print(f"• {tip}")
    else:
        print("• No suggestions—your password looks strong!")

def log_audit(password, score, crack_time):
    with open("audit_log.txt", "a") as log:
        log.write(f"{datetime.now()} | Password: {'*' * len(password)} | Score: {score} | Crack Time: {crack_time}\n")

def main():
    print("🔐 Password Strength Checker")
    password = getpass.getpass("Enter your password (input hidden): ")

    try:
        last_changed_days = int(input("How many days ago did you last change this password ? "))
        if last_changed_days > 90:
            print("⏳ Consider updating your password—it's over 90 days old.")
    except ValueError:
        print("⏳ Skipping age check (invalid input)")

    score, crack_time, feedback, patterns = analyze_password(password)
    display_results(password, score, crack_time, feedback, patterns)
    log_audit(password, score, crack_time)

if __name__ == "__main__":
    main()
