#!/usr/bin/env python3
import os
import subprocess
import time
from selenium import webdriver
from selenium.webdriver.common.by import By

def solve():
    img_file = "Pi7_edited-620765387-295401085-ab80a44e-e09f-4526-ac99-e3b24918b224.jpeg"
    
    # Kumpulan tebakan password dari tag EXIF "Artist" dan "Make"
    passwords = [
        "Jokowihebat", "Joko wihebat", "Jokowi hebat", "wihebatJoko", 
        "Joko", "wihebat", '"Joko" Is powerfull words', 
        '"wihebat" and this is also strong', 'Jokowi'
    ]
    
    print("[*] 1. Mencoba brute-force Steghide...")
    steghide_found = False
    for pwd in passwords:
        # Menjalankan steghide dengan format spasi yang benar
        result = subprocess.run(['steghide', 'extract', '-sf', img_file, '-p', pwd, '-f'], capture_output=True, text=True)
        if result.returncode == 0 or "wrote extracted data" in result.stdout or "wrote extracted data" in result.stderr:
            print(f"[+] Yessir! Steghide berhasil diekstrak dengan password: {pwd}")
            print(f"[*] Cek folder lu, pasti ada file baru yang keluar dari gambar itu!")
            steghide_found = True
            break
            
    if not steghide_found:
        print("[-] Steghide zonk. Lanjut hajar Emoji-AES!\n")
        
    print("[*] 2. Mencoba brute-force Emoji-AES (Rotasi 0-64) via Selenium...")
    emoji_text = "😫👪👷🙆👘👨😲👲👕👑👥👸👒😲👦👴🙉😸🙇👳🙂😷👘🙅👓😳😳🙆👔👢👺👤👺👕👱👑👱🙆👶👫👳👦😴👸👨👕👷👭👚🙈🙍😵👲👮"
    
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--log-level=3')
    
    try:
        driver = webdriver.Chrome(options=options)
        driver.get("https://emoji-aes.miaotony.xyz/")
        time.sleep(2)
        
        # Membuka menu Advanced untuk mengakses input Rotasi
        try:
            adv = driver.find_elements(By.XPATH, "//*[contains(text(), 'Advanced')]")
            if adv:
                adv[0].click()
                time.sleep(0.5)
        except:
            pass
            
        inputs = driver.find_elements(By.TAG_NAME, "input")
        msg_box = driver.find_elements(By.TAG_NAME, "textarea")[0]
        pass_box = [inp for inp in inputs if inp.get_attribute("type") in ["text", "password"]][0]
        btn_decrypt = [btn for btn in driver.find_elements(By.TAG_NAME, "button") if "decrypt" in btn.text.lower()][0]
        
        rot_box = None
        for inp in inputs:
            if inp.get_attribute("type") == "number":
                rot_box = inp
                break
                
        found = False
        print("[*] Sabar ya bro, lagi ngetes ratusan kombinasi rotasi x password...")
        for pwd in passwords:
            for rot in range(65):
                msg_box.clear()
                msg_box.send_keys(emoji_text)
                pass_box.clear()
                pass_box.send_keys(pwd)
                
                if rot_box:
                    rot_box.clear()
                    rot_box.send_keys(str(rot))
                    
                btn_decrypt.click()
                res = msg_box.get_attribute("value")
                
                # Validasi jika berhasil ter-decrypt jadi teks normal
                if "Error" not in res and len(res) > 0 and emoji_text[:5] not in res:
                    print(f"\n[+] BINGO! Emoji-AES berhasil di-decrypt!")
                    print(f"Password : {pwd}")
                    print(f"Rotasi   : {rot}")
                    print(f"Pesan    : {res}")
                    found = True
                    break
            if found:
                break
                
        if not found:
            print("[-] Emoji-AES brute-force gagal juga. Coba kita analisa ulang pesannya.")
            
        driver.quit()
    except Exception as e:
        print(f"[-] Error pas jalanin Selenium: {e}")

if __name__ == "__main__":
    solve()
