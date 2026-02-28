https://chatgpt.com/canvas/shared/68f482f3c66481919e4389f7e1ba3084
# Writeup — Leaky Login (Reverse)

**Challenge:** Leaky Login (Reverse, Baby)

**Author:** aria

**Ringkasan singkat**
Program `leaky_login` adalah sebuah binary ELF 64-bit yang meminta username dan password untuk menampilkan flag. Namun, kredensial dan flag ternyata sudah *embedded* di dalam binary sebagai JSON. Dengan membaca data statis dari binary (daripada menjalankannya dan mencoba bypass proteksi), kita dapat mengekstrak username/password/flag dengan sangat mudah.

---

## 1. File yang diberikan

* `leaky_login` (ELF 64-bit, PIE, not stripped)
* `flag.txt` (berisi flag hasil eksploitasi)

---

## 2. Recon / Informasi awal

Beberapa perintah penting yang dijalankan:

```bash
file leaky_login
# -> ELF 64-bit LSB pie executable, x86-64, not stripped

checksec --file=leaky_login
# -> Full RELRO, Canary found, NX enabled, PIE enabled, SHSTK, IBT, Stripped: No
```

Karena binary **tidak stripped** dan decompile menunjukkan fungsi `extract_value(creds_json, KEY, dst, size)`, ada indikasi bahwa kredensial dan flag di-embed di dalam binary sebagai JSON string (`creds_json`). Solusi yang paling aman dan cepat: **baca statis string dari binary**.

---

## 3. Analisis statis singkat (dari decompiler)

* Fungsi `main` memanggil `extract_value(creds_json, "user"/"pass"/"flag", dst, size)` tiga kali.
* Nilai yang diekstrak dibandingkan dengan input `Username` dan `Password` yang diminta dari `stdin`.
* Jika cocok, program menampilkan `Welcome <user>!` dan `Flag: <flag>`.

Kesimpulan: program tidak memanggil file eksternal untuk kredensial — semua sudah "tertulis" di binary.

---

## 4. Langkah ekstraksi (apa yang saya lakukan)

### 4.1 Menggunakan `strings`

Perintah yang dipakai:

```bash
strings -n 5 leaky_login | grep -E '"user"|"pass"|"flag"'
```

Output yang ditemukan:

```
{"user":"admin","pass":"letmein123","flag":"FGTE{REVERSE_LOGIN_LEAK}"}
```

### 4.2 Konfirmasi flag lain (opsional)

Perintah `grep -R FGTE` menunjukkan juga hasil di `flag.txt`:

```
flag.txt:FGTE{REVERSE_LOGIN_LEAK}
```

### 4.3 Menjalankan program dengan kredensial

Untuk memverifikasi, jalankan program dan masukkan kredensial:

```
$ ./leaky_login
Login
Username: admin
Password: letmein123
Welcome admin!
Flag: FGTE{REVERSE_LOGIN_LEAK}
```

---

## 5. PoC (proof of concept)

Cukup mengekstrak string JSON dari binary seperti di atas. Jika ingin otomatisasi, berikut contoh satu-liner yang juga bekerja:

```bash
strings -n 1 leaky_login | grep -o '{"user".*}'
```

Atau gunakan skrip Python sederhana yang mencari blob JSON dalam binary (berguna untuk format lebih kompleks), tetapi dalam kasus ini `strings` sudah cukup.

---

## 6. Lessons learned & mitigasi

**Mengapa ini bocor?**

* Developer menyimpan kredensial dan flag sebagai literal string di dalam binary. Ini memudahkan reverse engineer untuk menemukan credentials menggunakan tools standar (`strings`, `objdump`, `gdb`, dsb.).

**Mitigasi yang disarankan:**

* Jangan pernah menyimpan kredensial atau flag langsung di binary sebagai plaintext.
* Gunakan mekanisme pengambilan kredensial dari sumber yang aman (server remote, environment variables, vault) — dan pastikan flow otentikasi aman.
* Jika benar-benar perlu menyembunyikan data sensitif di binary untuk purpose tertentu, gunakan enkripsi dengan kunci yang tidak disimpan di binary (mis. KMS atau remote key retrieval) dan hindari hard-coded secrets.

---

## 7. Kesimpulan & hasil akhir

* Username: `admin`
* Password: `letmein123`
* Flag: `FGTE{REVERSE_LOGIN_LEAK}`

Metode yang dipakai: static analysis (strings / reading .rodata) — cepat, aman, dan efektif karena kredensial sudah tertanam di binary.

---

## 8. Perintah penting (rekap)

```bash
file leaky_login
checksec --file=leaky_login
strings -n 5 leaky_login | grep -E '"user"|"pass"|"flag"'
./leaky_login  # kemudian masukkan admin / letmein123
```

---

Jika kamu mau, saya bisa:

* Export halaman ini jadi file markdown `.md` untuk diunduh; atau
* Buat versi writeup dalam bahasa Inggris; atau
* Tambahkan screenshot/command output yang lebih rapi untuk dilampirkan di writeup.

Mau saya lanjutkan dengan salah satu opsi tersebut?
