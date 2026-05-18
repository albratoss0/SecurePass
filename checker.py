import math
import hashlib
import urllib.request
import urllib.error
import re
from utils import estimate_crack_time

def check_pwned(password):
    """
    Checks the 'Have I Been Pwned' database to see if the password has leaked.
    We use k-anonymity, which means we hash the password and only send the first 
    5 characters of the hash. This protects the user's actual password.
    """
    if not password:
        return 0
        
    # SHA-1 is standard for HIBP, even though it's not secure for storing passwords
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    # We only send the prefix over the network
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SecurePass-Client'})
        with urllib.request.urlopen(req, timeout=3) as response:
            res = response.read().decode('utf-8')
            
            # The API returns all suffixes that match our prefix. We check if ours is in there.
            for line in res.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return int(count)
        return 0
    except Exception:
        # If the API is down or we have no internet, we fail gracefully
        return -1

def analyze_password(pwd):
    """
    Looks at the password from multiple angles: character sets, length, 
    repeated patterns, and overall entropy (randomness).
    """
    if not pwd:
        return None
        
    # First, let's see what kind of characters they actually used
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_symbol = any(not c.isalnum() for c in pwd)
    
    # Calculate the size of the "pool" of characters they drew from
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 32
    
    # Entropy tells us how hard it is to guess mathematically
    entropy = len(pwd) * math.log2(charset_size) if charset_size > 0 else 0
    entropy = round(entropy, 1)
    
    # Normalize it into a 0-100 score for the UI progress bar
    score = min(100, int((entropy / 100) * 100))
    
    # Assign a human-readable strength and color for visual feedback
    if entropy < 40:
        strength = "Weak"
        color = "#d32f2f" # Red
    elif entropy < 70:
        strength = "Moderate"
        color = "#f57c00" # Orange
    else:
        strength = "Strong"
        color = "#388e3c" # Green
        
    # Check for lazy habits, like typing 'aaa' or '1111'
    has_repeat = bool(re.search(r'(.)\1{2,}', pwd))
        
    # Bundle everything up nicely for the UI to consume
    return {
        "length": len(pwd),
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "has_repeat": has_repeat,
        "entropy": entropy,
        "strength": strength,
        "score": score,
        "color": color,
        "crack_time": estimate_crack_time(entropy)
    }
