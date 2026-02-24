#!/usr/bin/env python3
import requests

TARGET_URL = "http://localhost:1337"
REGISTER_URL = f"{TARGET_URL}/register"
LOGIN_URL = f"{TARGET_URL}/login"

def check_cookies():
    s = requests.Session()
    # Register/Login user asal aja
    creds = {"username": "cek_cookie", "password": "123"}
    s.post(REGISTER_URL, data=creds)
    s.post(LOGIN_URL, data=creds)
    
    print("-" * 30)
    print("Daftar Cookie:")
    for name, value in s.cookies.items():
        print(f"Name: {name}")
        print(f"Value: {value[:20]}...") 
    print("-" * 30)

if __name__ == "__main__":
    check_cookies()
