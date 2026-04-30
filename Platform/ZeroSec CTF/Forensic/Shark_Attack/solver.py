#!/usr/bin/env python3
import re

def solve():
    print("[*] Analyzing corrupted PCAP file...")
    try:
        with open("chall.pcap", "rb") as f:
            data = f.read()
            
        # Mencari pattern flag ZeroSec{...} di dalam raw bytes
        matches = re.findall(rb"ZeroSec\{.*?\}", data)
        
        if matches:
            print("[+] Flag found!")
            for match in matches:
                print("FLAG :", match.decode('utf-8'))
        else:
            print("[-] Strict pattern not found, extracting all readable strings...")
            # Fallback: ekstrak semua printable string minimal 5 karakter
            strings = re.findall(rb"[ -~]{5,}", data)
            for s in strings:
                print(s.decode('utf-8'))
                
    except FileNotFoundError:
        print("[-] File chall.pcap tidak ditemukan. Pastikan ada di direktori yang sama.")

if __name__ == "__main__":
    solve()
