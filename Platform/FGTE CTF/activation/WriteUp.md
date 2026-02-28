https://chatgpt.com/share/68e7ce6b-5bdc-8002-83cb-96004a68d24d
# 🧩 Writeup — Activation (Reverse Engineering CTF)

## 📘 Challenge Overview

**Category:** Reverse Engineering
**Difficulty:** Easy–Medium
**Author:** aria

Challenge ini memberikan file **Activation.exe** yang berperan sebagai aplikasi aktivasi lisensi. Program akan meminta *username* dan *license key*, lalu menampilkan flag jika keduanya benar.

---

## 🔍 Analisis Awal

Saat dijalankan, program menampilkan prompt:

```
Enter username:
Enter license key:
```

Jika kombinasi benar → program akan menampilkan flag terenkripsi. Karena tidak ada input/output mencurigakan lain, maka logika aktivasi kemungkinan besar tersembunyi di dalam kode.

---

## 🧠 Decompiling .NET Binary

Karena binary berformat .NET, kita bisa menggunakan **dnSpy**, **ILSpy**, atau **dotPeek** untuk membaca source code C# secara langsung.

Berikut hasil dekompilasi bagian penting:

```csharp
private static readonly string[] userChunks = new string[] { "UkFOSQ==" };
private static readonly string[] saltChunks = new string[] {
    "c2FsdF9w",
    "YXJ0XzFf",
    "ZnJvbV9j",
    "cmU="
};

private static byte[] GetSalt()
{
    string text = string.Concat(saltChunks);
    return Convert.FromBase64String(text);
}

private static string ExpectedLicense(string username)
{
    byte[] salt = GetSalt();
    using (HMACSHA256 hmacsha = new HMACSHA256(salt))
    {
        byte[] array = hmacsha.ComputeHash(Encoding.UTF8.GetBytes(username));
        return BitConverter.ToString(array, 0, 8).Replace("-", string.Empty);
    }
}
```

Program juga memiliki blok dekripsi blob terenkripsi menggunakan AES-CBC:

```csharp
byte[] blob = new byte[] {
    167,164,179,68,122,43,220,205,221,237,252,140,94,60,228,168,
    158,24,12,211,42,196,123,129,112,31,108,142,85,169,138,71,
    23,244,193,140,102,155,201,244,183,5,176,49,163,24,215,196,
    212,215,159,80,85,221,12,234,16,7,169,163,172,218,85,246
};
```

---

## 🧩 Langkah-langkah Reverse

### 1. Mendapatkan Username

`"UkFOSQ=="` → Base64 decode → **"RANI"**

```
✅ username = RANI
```

### 2. Mendapatkan Salt

Gabungan saltChunks:
`c2FsdF9w` + `YXJ0XzFf` + `ZnJvbV9j` + `cmU=` = `c2FsdF9wYXJ0XzFfZnJvbV9jcmU=`
→ Base64 decode → **salt_part_1_from_cre**

```
✅ salt = b"salt_part_1_from_cre"
```

### 3. Membentuk License Key

License dibentuk dengan HMAC-SHA256 dari username dengan key = salt, lalu diambil 8 byte pertama hasil digest dan diubah ke HEX uppercase.

---

## ⚙️ Solver Script

```python
import base64
import hashlib
import hmac
from Crypto.Cipher import AES

# data dari program
username = "RANI"
salt = b"salt_part_1_from_cre"
encryptedBlob = bytes([
    167,164,179,68,122,43,220,205,221,237,252,140,94,60,228,168,
    158,24,12,211,42,196,123,129,112,31,108,142,85,169,138,71,
    23,244,193,140,102,155,201,244,183,5,176,49,163,24,215,196,
    212,215,159,80,85,221,12,234,16,7,169,163,172,218,85,246
])

# 1. license
digest = hmac.new(salt, username.encode(), hashlib.sha256).digest()
license_key = ''.join(f'{b:02X}' for b in digest[:8])
print(f"License: {license_key}")

# 2. derive key
salt_b64 = base64.b64encode(salt).decode()
data = (license_key + salt_b64).encode()
sha = hashlib.sha256(data).digest()
key = sha[:16]

# 3. decrypt blob
iv = encryptedBlob[:16]
ciphertext = encryptedBlob[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
# remove PKCS7 padding
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

print("Decrypted flag:", plaintext.decode())
```

---

## 💻 Output Eksekusi

```
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Reverse/activation]
└─$ python3 solver.py
License: 0905E413DDF6D48B
Decrypted flag: FGTE{L!c3n$3_4cTiv@t10n_7xY9_b2Q8R5s}
```

---

## 🏁 Final Flag

```
FGTE{L!c3n$3_4cTiv@t10n_7xY9_b2Q8R5s}
```

---

## 🧩 Kesimpulan

Challenge ini berfokus pada **analisis logika aktivasi software** yang melibatkan:

* **Base64 decoding** untuk username dan salt
* **HMAC-SHA256** sebagai generator license key
* **AES-CBC** untuk enkripsi flag dengan key turunan dari license dan salt

Prosesnya mencerminkan mekanisme *software licensing system* sederhana yang dienkripsi dan di-*obfuscate* dalam potongan array kecil. Dengan menganalisis kode sumber .NET, kita dapat sepenuhnya merekonstruksi proses aktivasi dan mengekstrak flag tanpa menjalankan program asli.
