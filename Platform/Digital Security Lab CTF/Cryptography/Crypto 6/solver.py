import requests
from Crypto.Util.number import long_to_bytes, inverse

# Konfigurasi Target
URL_BASE = "http://practice-digitalsecuritylab.di.unipi.it:11006/api/"

def solve():
    print("[*] Memulai RSA Chosen Ciphertext Attack...")

    # 1. Dapatkan Parameter (N, e, Encrypted Flag)
    try:
        resp = requests.get(URL_BASE + "get_params/")
        data = resp.json()
        
        n = int(data['n'])
        e = int(data['e'])
        c_flag = int(data['enc_flag'])
        
        print(f"[+] Parameter didapat:")
        print(f"    e = {e}")
        print(f"    n = {str(n)[:30]}...")
        print(f"    c = {str(c_flag)[:30]}...")

    except Exception as err:
        print(f"[-] Gagal mengambil parameter: {err}")
        return

    # 2. Siapkan Payload (Blinding)
    # Kita pilih faktor pengali S = 2
    # C_baru = C_flag * (2^e) mod n
    S = 2
    blinding_factor = pow(S, e, n)
    c_modified = (c_flag * blinding_factor) % n
    
    print(f"[*] Mengirim Ciphertext Modifikasi (C * 2^e)...")

    # 3. Kirim ke Oracle Decrypt
    try:
        payload = {"ct": c_modified}
        resp_dec = requests.post(URL_BASE + "rsa_decrypt/", json=payload).json()
        
        if "error" in resp_dec:
            print(f"[-] Oracle Error: {resp_dec['error']}")
            return
            
        p_modified = int(resp_dec['pt'])
        print(f"[+] Terima Plaintext Modifikasi (Flag * 2): {str(p_modified)[:30]}...")

    except Exception as err:
        print(f"[-] Gagal dekripsi: {err}")
        return

    # 4. Recover Flag
    # Flag = Plaintext_Modifikasi * inverse(2, n) mod n
    # Atau sederhananya dibagi 2
    print("[*] Memulihkan Flag Asli...")
    
    flag_int = (p_modified * inverse(S, n)) % n
    # flag_int = p_modified // 2  <-- Ini juga bisa jika p_modified < n
    
    flag_bytes = long_to_bytes(flag_int)
    
    print("\n" + "="*40)
    print(f"[+] FLAG: {flag_bytes.decode()}")
    print("="*40)

if __name__ == "__main__":
    solve()
