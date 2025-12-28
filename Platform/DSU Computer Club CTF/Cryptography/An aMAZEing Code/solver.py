import re

# Teks referensi dari halaman pertama "The Maze Runner" (Chapter 1)
# Kita menggunakan teks standar dari paragraf pembuka untuk mapping indeks.
book_text = """
He began his new life standing up, surrounded by cold darkness and stale, dusty air. 
Metal ground against metal; a lurching shudder shook the floor beneath him. 
He fell down at the sudden movement and shuffled backward on his hands and feet, 
drops of sweat beading on his forehead despite the cool air. 
His back struck a hard metal wall; he slid along it until he hit the corner of the room. 
Sinking to the floor, he pulled his legs up tight against his body, hoping his eyes would adjust to the absolute darkness. 
With another jolt, the room jerked upward like an old elevator in a harsh voice. 
Harsh sounds of chains and pulleys, like the workings of an ancient steel factory, echoed through the room, bouncing off the walls with a hollow, tinny whine. 
The lightless elevator swayed back and forth as it ascended, turning slowly around its vertical axis; each revolution made his stomach lurch. 
He wanted to cry out, but no sound came from his throat; his attempted scream was nothing but a silent rush of air.
"""

def solve():
    # 1. Parsing Teks: Ambil hanya kata-kata, abaikan tanda baca
    words = re.findall(r'\b\w+\b', book_text)
    
    # 2. Definisi Ciphertext
    # Format: List of lists, di mana setiap sub-list adalah satu kata dalam pesan akhir
    # Cipher: 64 24 6 / 106 153 / 32 3 124 / 78 20 17 139 8
    cipher_indices = [
        [64, 24, 6],           
        [106, 153],            
        [32, 3, 124],          
        [78, 20, 17, 139, 8]   
    ]

    print("[*] Starting Decryption based on 'The Maze Runner' Page 1...")
    
    decoded_message_parts = []
    
    for group in cipher_indices:
        part_string = ""
        for index in group:
            # Cek range index
            if 0 < index <= len(words):
                # Python list is 0-indexed, book cipher is 1-indexed
                word = words[index - 1]
                char = word[0] # Ambil huruf pertama
                part_string += char
                # Uncomment baris di bawah untuk debug mapping per kata
                # print(f"Index {index}: {word} -> {char}")
            else:
                part_string += "?"
                print(f"Warning: Index {index} out of range (Max: {len(words)})")
        
        decoded_message_parts.append(part_string)

    # 3. Formatting Output
    full_message_spaced = " ".join(decoded_message_parts).upper()
    full_message_nospace = "".join(decoded_message_parts).upper()
    
    print(f"\n[+] Decoded Words: {full_message_spaced}")
    print(f"[+] Flag: DSU{{{full_message_nospace}}}")

if __name__ == "__main__":
    solve()
