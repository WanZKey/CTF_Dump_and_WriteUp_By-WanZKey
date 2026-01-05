import hashlib
import itertools

def generate_leet_variations(text):
    # Common leetspeak substitutions
    leet_map = {
        'a': '4',
        'e': '3',
        'i': '1',
        'o': '0',
        's': '5',
        't': '7'
    }
    
    # Get all possible positions where we can make one leetspeak substitution
    positions = []
    for i, char in enumerate(text):
        if char.lower() in leet_map:
            positions.append(i)
    
    variations = []
    # Try each position one at a time (since intel says "one, only one!")
    for pos in positions:
        new_text = list(text)
        char = text[pos].lower()
        if char in leet_map:
            new_text[pos] = leet_map[char]
            variations.append(''.join(new_text))
    
    return variations

def generate_special_chars():
    return ['!', '@', '#', '$', '%', '^', '&', '*', '?', '_']

def generate_common_pins():
    # Common 4-digit PINs
    common_pins = [
        '0000', '1234', '1111', '2222', '3333', '4444', 
        '5555', '6666', '7777', '8888', '9999', '2580',
        '1212', '1122', '1313', '1414', '1515', '2000',
        '2001', '2002', '2003', '2004', '2005', '2006',
        '2007', '2008', '2009', '2010', '2011', '2012',
        '2013', '2014', '2015', '2016', '2017', '2018',
        '2019', '2020', '2021', '2022', '2023', '2024'
    ]
    return common_pins

def create_password_candidates():
    base = "yoshiethehomie"
    variations = generate_leet_variations(base)
    special_chars = generate_special_chars()
    pins = generate_common_pins()
    
    candidates = []
    
    for variation in variations:
        for char in special_chars:
            # Try special char at different positions
            for i in range(len(variation) + 1):
                temp = variation[:i] + char + variation[i:]
                for pin in pins:
                    # Create password with bctf{} format
                    password = f"bctf{{{temp}{pin}}}"
                    candidates.append(password)
    
    return candidates

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    target_hash = "ea23f261fff0ebc5b0a5d74621218e413a694ed0815a90615cf6edd7b49e6d0d"
    
    print("Starting password cracking...")
    print("Generating password candidates...")
    
    candidates = create_password_candidates()
    print(f"Generated {len(candidates)} candidates to test")
    
    for candidate in candidates:
        if hash_password(candidate) == target_hash:
            print(f"\nFound matching password: {candidate}")
            return
        
    print("\nNo matching password found")

if __name__ == "__main__":
    main()
