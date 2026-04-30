#!/usr/bin/env python3
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def solve():
    print("[*] Membuka web mirror Emoji-AES (miaotony.xyz) via Selenium...")
    
    # Setup headless browser agar berjalan di background terminal
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--log-level=3')
    
    try:
        driver = webdriver.Chrome(options=options)
        
        # Menggunakan mirror web Emoji-AES yang masih aktif
        driver.get("https://emoji-aes.miaotony.xyz/")
        
        emoji_text = "😫👪👷🙆👘👨😲👲👕👑👥👸👒😲👦👴🙉😸🙇👳🙂😷👘🙅👓😳😳🙆👔👢👺👤👺👕👱👑👱🙆👶👫👳👦😴👸👨👕👷👭👚🙈🙍😵👲👮"
        password = "Jokowihebat" # Gabungan dari 'Joko' dan 'wihebat'
        
        print(f"[*] Memasukkan Ciphertext Emoji-AES...")
        print(f"[*] Mengeksekusi dekripsi dengan key: {password}")
        
        # Mencari text area untuk input ciphertext
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        if textareas:
            textareas[0].send_keys(emoji_text)
            
        # Mencari field password
        inputs = driver.find_elements(By.TAG_NAME, "input")
        for inp in inputs:
            if inp.get_attribute("type") in ["text", "password"]:
                inp.send_keys(password)
                break
                
        # Mencari dan mengklik tombol Decrypt
        buttons = driver.find_elements(By.TAG_NAME, "button")
        for btn in buttons:
            if "decrypt" in btn.text.lower() or "解密" in btn.text.lower():
                btn.click()
                break
                
        # Menunggu sebentar hingga DOM terupdate
        time.sleep(2)
        
        # Mengambil hasil dekripsi
        result = textareas[0].get_attribute("value")
        print("\n[+] Hasil Decrypt (Nomor HP):")
        print(result)
        
        driver.quit()
        
    except Exception as e:
        print("[-] Error saat menjalankan script otomatisasi Selenium:", e)
        print("\n[*] We got this bro! Kalau scriptnya gagal karena beda driver, lu bisa langsung kunjungi link mirror-nya di browser lu:")
        print("👉 https://emoji-aes.miaotony.xyz/")
        print("Password: Jokowihebat")

if __name__ == "__main__":
    solve()
