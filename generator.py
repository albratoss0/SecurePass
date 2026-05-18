import secrets
import string

# A curated list of easy-to-visualize words for passphrases
WORDS = [
    "ocean", "tiger", "river", "mountain", "eagle", "forest", "shadow", "winter",
    "summer", "spring", "autumn", "breeze", "storm", "thunder", "cloud", "star",
    "planet", "galaxy", "comet", "meteor", "dragon", "knight", "castle", "sword",
    "shield", "magic", "wizard", "potion", "crystal", "diamond", "ruby", "emerald",
    "sapphire", "gold", "silver", "bronze", "iron", "steel", "copper", "stone"
]

def generate_secure(length=16):
    """
    Generates a cryptographically secure, fully random password.
    It guarantees a mix of all character types so it passes strict requirements.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        # secrets is much safer than random for security purposes
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Keep generating until we hit all the mandatory checks
        if (any(c.islower() for c in pwd) and 
            any(c.isupper() for c in pwd) and 
            sum(c.isdigit() for c in pwd) >= 2 and 
            any(not c.isalnum() for c in pwd)):
            return pwd

def generate_passphrase(words_count=4):
    """
    Generates a 'Correct Horse Battery Staple' style passphrase.
    These are highly secure due to length but much easier for humans to remember.
    """
    # Pick random words and capitalize them for readability
    chosen = [secrets.choice(WORDS).capitalize() for _ in range(words_count)]
    separators = ['!', '_', '-', '@', '#', '.']
    
    pwd = ""
    for i, word in enumerate(chosen):
        pwd += word
        
        # Inject separators and occasionally random numbers between words to satisfy complexity rules
        if i < len(chosen) - 1:
            pwd += secrets.choice(separators)
            if secrets.choice([True, False]): # 50% chance to add a number
                pwd += str(secrets.randbelow(100))
            pwd += secrets.choice(separators)
            
    # Clean up any double separators that might have formed
    return pwd.replace("!!", "!").replace("__", "_")

def generate_pin(length=6):
    """Generates a secure numeric PIN code."""
    # Simple and direct: just pick random digits
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))
