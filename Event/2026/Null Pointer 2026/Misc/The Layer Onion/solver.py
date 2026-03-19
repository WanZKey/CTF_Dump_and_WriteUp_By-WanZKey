#!/usr/bin/env python3
import os
import tarfile
import zipfile
import gzip
import bz2
import shutil

def check_magic_bytes(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read(2)
    except IOError:
        return b''

def peel_the_onion(start_file):
    current_file = start_file 
    counter = 0 # Menggunakan angka untuk nama file agar tidak kepanjangan
    
    while True:
        print(f"Extracting: {current_file}")
        
        if not os.path.exists(current_file):
            print(f"Hold up bro, {current_file} is missing.")
            break

        extracted_file = None
        magic_bytes = check_magic_bytes(current_file)

        # Handle tar files
        if tarfile.is_tarfile(current_file):
            with tarfile.open(current_file, 'r') as tar:
                members = tar.getnames()
                if members:
                    extracted_file = members[0]
                    tar.extractall()
                    
        # Handle zip files
        elif zipfile.is_zipfile(current_file):
            with zipfile.ZipFile(current_file, 'r') as zip_ref:
                members = zip_ref.namelist()
                if members:
                    extracted_file = members[0]
                    zip_ref.extractall()
                    
        # Handle gzip files (magic bytes: 1f 8b)
        elif magic_bytes == b'\x1f\x8b':
            extracted_file = f"layer_extracted_{counter}"
            with gzip.open(current_file, 'rb') as f_in:
                with open(extracted_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

        # Handle bzip2 files (magic bytes: 42 5a / 'BZ')
        elif magic_bytes == b'BZ':
            extracted_file = f"layer_extracted_{counter}"
            with bz2.open(current_file, 'rb') as f_in:
                with open(extracted_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
        # Hit the bottom layer or unknown format
        else:
            print(f"\nWe hit the bottom! The final file is: {current_file}")
            print("Trying to read the contents...")
            try:
                with open(current_file, 'r') as f:
                    print(f"Flag or Text:\n{f.read()}")
            except UnicodeDecodeError:
                print("Not a standard text file bro. Run 'file' command on it to see what it is.")
            break

        if extracted_file:
            # Clean up file sebelumnya agar tidak menumpuk
            if current_file not in ["onion.zip", "layer_1499.gz"]:
                try:
                    os.remove(current_file)
                except OSError:
                    pass
            current_file = extracted_file
            counter += 1
        else:
            print("Oh my bad, ran into an empty archive.")
            break

if __name__ == "__main__":
    # Karena kamu sudah punya layer_1499.gz, kita mulai dari sini saja
    peel_the_onion("layer_1499.gz")
