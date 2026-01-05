from pwn import *

# Konfigurasi Koneksi
HOST = 'gzcli.1pc.tf'
PORT = 52206

# Database Jawaban (Sudah diverifikasi manual olehmu)
answers = {
    "StorageChallenge1": 3,
    "StorageChallenge2": 2,
    "StorageChallenge3": 0,
    "StorageChallenge4": 0,
    "StorageChallenge5": 3,
    "StorageChallenge6": 0,
    "StorageChallenge7": 0,
    "StorageChallenge8": 6,
    "StorageChallenge9": 24,
    "StorageChallenge10": 2,
    "Hell_0": 28
}

def start():
    # Setup koneksi
    r = remote(HOST, PORT)

    # Urutkan kunci berdasarkan panjang string (Descending)
    # PENTING: Agar StorageChallenge10 dideteksi sebelum StorageChallenge1
    sorted_contracts = sorted(answers.keys(), key=len, reverse=True)

    try:
        while True:
            # Terima data
            # Gunakan timeout kecil agar tidak hang jika server lambat
            output = r.recvuntil(b'Answer:', drop=False).decode()
            print(output)

            current_contract = None
            
            # Deteksi kontrak yang sedang aktif
            for contract_name in sorted_contracts:
                if f"contract {contract_name}" in output:
                    current_contract = contract_name
                    break
            
            if current_contract:
                ans = answers[current_contract]
                print(f"[+] Detected: {current_contract} -> Sending Answer: {ans}")
                r.sendline(str(ans).encode())

                # [FIX UTAMA] Penanganan Khusus Final Boss
                # Setelah jawab Hell_0, jangan loop lagi cari "Answer:", langsung ambil Flag!
                if current_contract == "Hell_0":
                    print("[*] Final answer sent! Receiving Flag...")
                    # Baca semua sisa output sampai koneksi ditutup server
                    final_output = r.recvall().decode()
                    print(final_output)
                    break 
            else:
                # Fallback jika pola tidak dikenali
                pass

    except EOFError:
        # Menangani jika koneksi putus tiba-tiba (biasanya flag ada di buffer terakhir)
        print("[-] Connection Closed by Server.")
        try:
            # Coba ambil sisa data yang mungkin belum tercetak
            print(r.recvall().decode())
        except:
            pass
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        r.close()

if __name__ == "__main__":
    start()
