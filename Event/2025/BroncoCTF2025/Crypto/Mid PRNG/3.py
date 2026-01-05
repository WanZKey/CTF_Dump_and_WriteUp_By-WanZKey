from pwn import *

def analyze_samples(num_samples=5):
    # Connect to server and get samples
    samples = []
    for _ in range(num_samples):
        try:
            r = remote('bad-prng.nc.broncoctf.xyz', 8000)
            sample = r.recvline().strip().decode()
            samples.append(bytes.fromhex(sample))
            r.close()
        except:
            continue
    return samples

def find_prng_pattern(samples):
    # Convert samples to list of integers for easier analysis
    int_samples = [[b for b in sample] for sample in samples]
    
    # Analyze differences between consecutive bytes
    differences = []
    for sample in int_samples:
        sample_diff = []
        for i in range(len(sample)-1):
            sample_diff.append(sample[i+1] - sample[i])
        differences.append(sample_diff)
    
    return differences

def attempt_decrypt(sample, pattern):
    # Known start of flag
    known = b'bronco{'
    key_start = bytes([a ^ b for a, b in zip(sample[:len(known)], known)])
    
    # Try to predict rest of key using pattern
    predicted_key = bytearray(key_start)
    for i in range(len(sample) - len(known)):
        if i < len(pattern):
            next_byte = (predicted_key[-1] + pattern[i]) & 0xFF
            predicted_key.append(next_byte)
    
    # Decrypt using predicted key
    return bytes([a ^ b for a, b in zip(sample, predicted_key)])

# Get multiple samples
samples = analyze_samples(5)
patterns = find_prng_pattern(samples)

print("Analyzing PRNG patterns...")
for i, pattern in enumerate(patterns):
    print(f"\nPattern {i}:", pattern[:10], "...")
    
# Try decrypting with detected patterns
for i, sample in enumerate(samples):
    print(f"\nTrying sample {i}:")
    for j, pattern in enumerate(patterns):
        decrypted = attempt_decrypt(sample, pattern)
        if all(32 <= c <= 126 for c in decrypted[7:-1]):  # Check if printable ASCII
            print(f"Using pattern {j}:", decrypted)
