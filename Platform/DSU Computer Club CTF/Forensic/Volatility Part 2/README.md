# DSU CTF 2025: Volatility Part 2 Writeup

**Category:** Forensics
**Points:** 375
**Author:** Jacob R.

## Deskripsi Challenge

> Before my computer crashed, I had been in the middle of painting a second flag as well. Can you look around the memory dump some more and see if you can recover the flag I was painting? Oh, and for whatever reason, paint gave my BGR .bmp flag painting dimensions of width 614 px and height 460 px. Maybe that'll help you recover it more efficiently, I dunno. Just get me my painting back please!

**Note:** Use the same memory dump from Part 1 for this challenge (`WORKSTATION-20251203-221315.raw`).

## Langkah Pengerjaan

### 1. Identifikasi Proses Target

Tantangan ini meminta kita untuk memulihkan gambar yang sedang dilukis di **Microsoft Paint** sebelum sistem crash. Berdasarkan analisis `windows.cmdline` pada Volatility Part 1, kita mengetahui bahwa proses `mspaint.exe` berjalan dengan Process ID (PID) **4092**.

```text
PID     Process Args
...
4092    mspaint.exe     "C:\Windows\system32\mspaint.exe"
...

```

### 2. Dumping Memori Proses

Langkah selanjutnya adalah mengambil (dump) seluruh memori yang dialokasikan untuk proses `mspaint.exe` (PID 4092). Kita menggunakan plugin `memdump` pada Volatility 2.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Volatility Part 1]
└─$ vol2 -f WORKSTATION-20251203-221315.raw --profile=Win7SP1x64 memdump -p 4092 --dump-dir .
Volatility Foundation Volatility Framework 2.6
************************************************************************
Writing mspaint.exe [  4092] to 4092.dmp

```

Perintah ini menghasilkan file memory dump mentah bernama `4092.dmp`.

### 3. Persiapan File untuk GIMP

Kita akan menggunakan GIMP untuk membuka data memori mentah ini sebagai gambar. Namun, jika kita mencoba membuka file dengan ekstensi `.dmp` atau `.raw` secara langsung, GIMP sering salah mengartikannya sebagai file RAW kamera digital dan akan menampilkan error karena tidak memiliki loader yang sesuai.

Untuk mengatasi ini, kita mengubah ekstensi file menjadi `.data` agar GIMP tidak mencoba mendeteksinya secara otomatis dan memungkinkan kita memilih tipe "Raw Image Data" secara manual.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Volatility Part 1]
└─$ mv 4092.dmp mspaint.data

```

### 4. Recovery Gambar dengan GIMP

Kita membuka file `mspaint.data` di GIMP menggunakan opsi **File > Open**, dan memilih **"Raw Image Data"** pada pilihan tipe file di pojok kanan bawah dialog pembuka.

Pada jendela dialog "Load Image from Raw Data", kita perlu memasukkan parameter yang tepat agar data biner dapat diinterpretasikan sebagai gambar. Berdasarkan deskripsi soal dan hasil percobaan (trial and error) untuk menemukan lokasi offset yang tepat di dalam dump memori yang besar, berikut adalah konfigurasi yang berhasil:

* **Image Type:** RGB (Microsoft Paint biasanya menggunakan format BGR).
* **Offset:** 11327309 (Lokasi di mana data bitmap dimulai dalam dump memori).
* **Width:** 614 (Sesuai deskripsi soal).
* **Height:** 400 (Tinggi yang cukup untuk menampilkan area gambar yang relevan).
* **Palette Type:** B, G, R, X (BMP style) - Ini penting untuk mengatasi format warna Windows yang urutannya Biru-Hijau-Merah.

Berikut adalah tangkapan layar konfigurasi GIMP yang berhasil menampilkan gambar yang tersembunyi, meskipun masih dalam keadaan terbalik:

### 5. Finalisasi Gambar

Gambar yang berhasil di-load muncul dalam keadaan terbalik secara vertikal. Hal ini normal karena cara Microsoft Windows menyimpan data bitmap (BMP) di memori seringkali dimulai dari baris paling bawah ke atas.

Untuk membaca flagnya, kita membalik gambar tersebut di GIMP menggunakan menu **Image > Transform > Flip Vertically**.

Hasil akhirnya adalah gambar yang berisi pesan dan flag:

Flag terlihat jelas di bagian bawah gambar.

## Flag

`DSU{d1gg1ng_for_your_flags}`
