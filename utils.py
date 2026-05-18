import math
from datetime import datetime
import os

def estimate_crack_time(entropy):
    """
    Figuring out how long it takes to crack a password isn't an exact science, 
    but we can estimate it based on bits of entropy. We assume a modern GPU 
    can guess about 10 billion times per second.
    """
    try:
        # Total possible combinations divided by guesses per second
        seconds = (2 ** entropy) / 10_000_000_000
        
        # Format the output so it's easy for humans to read
        if seconds < 60:
            return f"{round(seconds, 2)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 1)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 1)} days"
        else:
            years = int(seconds / 31536000)
            return f"{years:,} years"
    except OverflowError:
        # If the password is so strong that the math breaks, it's safe to say it'll take a while!
        return "Countless millennia"

def save_report(password, analysis):
    """
    Saves a text report of the password analysis. This is great for keeping 
    a physical or local record of password strength policies.
    """
    # Create a unique filename using the current time so we don't overwrite older reports
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"securepass_report_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== SecurePass Strength Report ===\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Strength Rating: {analysis['strength']}\n")
        f.write(f"Estimated Entropy: {analysis['entropy']} bits\n")
        f.write(f"Estimated Crack Time: {analysis['crack_time']}\n\n")
        
        f.write("--- Detailed Breakdown ---\n")
        f.write(f"Length: {analysis['length']} (Recommended 16+)\n")
        f.write(f"Uppercase: {'Yes' if analysis['has_upper'] else 'No'}\n")
        f.write(f"Lowercase: {'Yes' if analysis['has_lower'] else 'No'}\n")
        f.write(f"Number: {'Yes' if analysis['has_digit'] else 'No'}\n")
        f.write(f"Symbol: {'Yes' if analysis['has_symbol'] else 'No'}\n")
        
        # If they've been pwned, make sure it stands out in the report
        if analysis.get('pwned_count', 0) > 0:
            f.write(f"\nWARNING: Password found in {analysis['pwned_count']:,} known data breaches!\n")
            
    return os.path.abspath(filename)
