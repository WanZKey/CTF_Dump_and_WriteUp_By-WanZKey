from pwn import *
import time

def get_sample():
    try:
        r = remote('bad-prng.nc.broncoctf.xyz', 8000)
        sample = r.recvline().strip().decode()
        r.close()
        return bytes.fromhex(sample)
    except:
        return None

def analyze_mt19937_possibility(samples):
    # Convert samples to 32-bit integers
    nums = []
    for sample in samples:
        for i in range(0, len(sample), 4):
            if i + 4 <= len(sample):
                nums.append(int.from_bytes(sample[i:i+4], 'big'))
    return nums

def try_crack_flag(sample):
    known = b'bronco{'
    result = bytearray()
    
    # Try different offsets
    for offset in range(4):
        key = bytearray()
        for i in range(0, len(sample)-offset, 4):
            if i+4 <= len(sample):
                val = int.from_bytes(sample[i:i+4], 'big')
                # Try to predict next value based on common PRNG patterns
                next_val = (val * 1103515245 + 12345) & 0xffffffff
                key.extend(next_val.to_bytes(4, 'big'))
        
        # XOR with sample
        for i in range(len(sample)):
            if i < len(key):
                result.append(sample[i] ^ key[i])
    
    return result

# Collect multiple samples with timing information
samples = []
timestamps = []

print("Collecting samples...")
for _ in range(5):
    timestamp = int(time.time())
    sample = get_sample()
    if sample:
        samples.append(sample)
        timestamps.append(timestamp)
        print(f"Sample {len(samples)}: {sample.hex()}")
        print(f"Timestamp: {timestamp}")
    time.sleep(1)  # Wait 1 second between samples

print("\nAnalyzing samples...")
for i, sample in enumerate(samples):
    print(f"\nTrying sample {i}:")
    result = try_crack_flag(sample)
    
    # Check if result might be valid flag
    if b'bronco{' in result:
        print(f"Possible flag found: {result}")
        
    # Also try with timestamp as seed
    timestamp = timestamps[i]
    for offset in range(-5, 6):  # Try nearby timestamps
        test_time = timestamp + offset
        seed = test_time & 0xffffffff
        key = bytearray()
        val = seed
        for _ in range(len(sample)):
            val = (val * 1103515245 + 12345) & 0xffffffff
            key.append(val & 0xff)
        decoded = bytes([a ^ b for a, b in zip(sample, key)])
        if b'bronco{' in decoded:
            print(f"Possible flag with timestamp {test_time}: {decoded}")
