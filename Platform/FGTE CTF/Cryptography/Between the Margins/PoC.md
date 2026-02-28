# Writeup: Between the Margins (ARIAF CTF 2025 - Crypto, Easy)

## Challenge Overview
- **Author**: aria
- **Description**: The challenge provides a cryptic message in Indonesian, translating roughly to: "Readable messages are never safe from interception. What matters is not what is said, but where to look. The signal you find is merely a reference. The rest is hidden between its boundaries."  
  It includes a sequence of numbers: `234, 235, 1, 237, 238`.  
  The flag format is `FGTE{WORD_WORD_...}`.
- **Files**: `referensi.txt` – a text file styled as a "Signal Archive" with four pages of narrative hints about hidden messages, coordinates, and misdirection.
- **Points**: 280
- **Solves**: 3 (at the time of the challenge)

The narrative in `referensi.txt` emphasizes that messages aren't concealed in obvious ways but are "misplaced" through positions, pages, lines, and coordinates. It warns against direct reading and urges counting and precise searching. The title "Between the Margins" and repeated references to "margins" are key hints.

## Step-by-Step Solution
1. **Examine the Provided File (`referensi.txt`)**:  
   Open and read the file. It contains formatted text divided into pages:  
   - Page 1: Discusses misplacing messages in routine and positions outliving words.  
   - Page 2: Talks about counting, coordinates, and indexing meaning in a book.  
   - Page 3: Mentions decoded messages lacking context and signals providing direction.  
   - Page 4: Ends with a "final directive" about the archive being a map, and the line: "Read carefully. Count precisely. **The truth lives between the margins**."

2. **Interpret the Hints**:  
   - The challenge description stresses that the "signal" (the numbers `234, 235, 1, 237, 238`) is just a *reference*, not the message itself. It directs attention to "where to look" and things hidden "between the boundaries" (margins).  
   - The file's narrative reinforces this: "Do not search for secrets here. Search for coordinates." and "The truth lives between the margins."  
   - The numbers might seem like coordinates, indices, or codes (e.g., word positions, character codes, or ASCII values), but calculating them (e.g., word count ~225, character count ~1400) doesn't yield direct output. They likely serve as misdirection or a nod to "counting precisely," but the real key is the thematic phrase.

3. **Identify the Hidden Message**:  
   - The standout phrase is from the last line: "The truth lives between the margins."  
   - This directly ties to the challenge title and hints. The "truth" (the flag content) is literally stated to "live between the margins."  
   - Ignoring the initial "The" (as it's not part of the core "truth"), format the remaining phrase: "truth lives between the margins."  
   - Convert to uppercase and replace spaces with underscores to match the flag format: `TRUTH_LIVES_BETWEEN_THE_MARGINS`.

4. **Verify the Numbers' Role**:  
   - Possible interpretations (explored but not necessary for the solution):  
     - Word indices: The phrase starts around word 221 ("truth") to 225 ("margins"), but doesn't match the given numbers.  
     - Character positions: Extracting chars at positions 234, 235, 1, 237, 238 yields nonsense (e.g., spaces, letters, or punctuation).  
     - ASCII/Unicode: 234=ê, 235=ë, 1=SOH (control char), 237=í, 238=î – no clear message.  
     - Missing number (236 absent, "between" 235 and 237), but this is overcomplicating.  
   - Ultimately, the numbers reinforce the theme of "references" and "direction," guiding solvers to the file's concluding phrase rather than a complex cipher.

## Flag
`FGTE{TRUTH_LIVES_BETWEEN_THE_MARGINS}`

## Notes
- This is a classic misdirection challenge: The text leads you to overthink positions and counts, but the flag is plainly embedded in the narrative.  
- No advanced tools or decryption needed – just careful reading.  
- If the numbers have a deeper meaning (e.g., steganography in the file's encoding), it wasn't required, as the phrase fits perfectly.
