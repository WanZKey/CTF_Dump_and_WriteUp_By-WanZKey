Enigmatic Curves
300
A scrambled rotor stream hides a curve and points; recover the start positions to read the stage-1 note. Solve the discrete log on the given elliptic curve to reveal the session secret. Use that secret (and your rotor starts) to unmask the final message.

Submit flag in format DSU{}

Author: Muhammad Essa

Hint
×
The payload is Base85 → JSON. init_positions_masked is XOR’d with sha256(b"note"+i)[0] & 0x1F (so you can unmask it). Use baby-step/giant-step on the given curve (p,a,b,G,Q) to find k such that k·G=Q. Finally, derive the keystream with sha256(str(k)+concat(init_positions)) and XOR with the final ciphertext. If the result looks wrong, try a small window around k (off-by-one is common).
