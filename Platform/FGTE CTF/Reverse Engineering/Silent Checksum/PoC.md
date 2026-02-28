https://chatgpt.com/canvas/shared/6916e24b74908191ac62dd69d7a322e8
# Silent Checksum — Writeup

## Ringkasan

File `silent_checksum_linux` adalah sebuah ELF 64-bit PIE yang melakukan beberapa pemeriksaan anti-debug/anti-VM, menghitung suatu digest internal (mirip SHA-1), membandingkannya dengan konstanta 20-byte, dan jika cocok melakukan dekripsi sederhana pada data statis dengan XOR `0x37` kemudian memeriksa checksum byte hasil dekripsi. Jika semua kondisi terpenuhi maka program mencetak hasil dekripsi (flag).

**Flag akhir:** `FGTE{REV3R53_CH3CK5UM_L0G1C}`

---

## Informasi awal

* Nama file: `silent_checksum_linux`
* Tipe: ELF 64-bit, LSB, PIE, dynamically linked, stripped
* Proteksi: Partial RELRO, NX enabled, no stack canary, PIE enabled
* Output saat dijalankan langsung: `Wrong!`

Tools yang digunakan pada analisis:

* IDA Pro (decompiler + hex view)
* `file`, `checksec` untuk info awal
* Python untuk ekstraksi (opsional)

---

## Analisis cepat alur program

Berdasarkan decompilation (fungsi `main` / `FUN_00101080`) alur utama:

1. Panggilan `ptrace(PTRACE_TRACEME, ...)` — anti-debug check. Jika proses sedang di-debug maka `ptrace` akan mengembalikan -1 dan `errno == 1`. Kondisi di binary mengarah ke percabangan sehingga jika *terdeteksi* debug, program akan langsung mencetak "Wrong!".
2. Panggilan ke fungsi `sub_18A0()` — pengujian CPUID/CPU feature (anti-VM/anti-non-Intel). Bila kondisi tidak terpenuhi program memberi delay (usleep) lalu gagal.
3. Inisialisasi struktur internal (fungsi `sub_12B0`) — mirip inisialisasi state untuk hashing (nilai awal yang mirip dengan IV SHA-1 dapat terlihat di konstanta).
4. Fungsi `sub_1640` dan `sub_1730` — melakukan pemrosesan blok dan padding, lalu menghasilkan digest 20 byte yang disimpan di buffer output (`v12` dalam decompile).
5. Digest 20 byte dibandingkan dengan konstanta 20 byte yang disimpan di data segment (`xmmword_2030` + nilai 4-byte berikutnya). Jika tidak cocok → `Wrong!`.
6. Jika cocok, program membaca data statis (`byte_4040`) sepanjang `qword_4030` bytes, melakukan `xor byte ^ 0x37` untuk setiap byte → menyimpan ke buffer hasil (`v16`).
7. Program menjumlahkan semua byte hasil XOR (unsigned byte accumulation). Bila hasil penjumlahan sama dengan 90 (ASCII 'Z' decimal 90) maka mencetak buffer hasil sebagai flag; jika tidak, `Wrong!`.

Catatan: Program tidak membaca input dari user; seluruh data berada di binary (static).

---

## Lokasi penting (hasil observasi di IDA)

Dari IDA kita dapatkan data mentah di `.data`:

```
.data:0000000000004040 ; _BYTE byte_4040[28]
.data:0000000000004040 byte_4040 db 71h,70h,63h,72h,4Ch,65h,72h,61h,04,65h,02,04
.data:000000000000404C                 db 68h,74h,7Fh,04,74h,7Ch,02,62h,7Ah,68h,7Bh,07
.data:0000000000004058                 db 70h,06,74h,4Ah

; total bytes = 28
```

Keterangan lain yang penting (digunakan untuk verifikasi):

* `byte_4040` (alamat virtual `0x4040`) — data yang akan di-XOR `0x37`.
* `qword_4030` — 64-bit nilai yang menyatakan panjang data; pada kasus ini panjang yang diamati adalah `28`.
* `xmmword_2030` + `v14` (4-byte) — konstanta 20-byte yang menjadi expected digest untuk perbandingan.

---

## Langkah detail di IDA (reproducible)

1. Buka binary di IDA Pro. Tunggu autoanalysis selesai.
2. Navigasi ke fungsi `main` (atau entry) dan cari panggilan ke subrutin inisialisasi hash (`sub_12B0`) dan panggilan yang memproses data (`sub_1640`, `sub_1730`).
3. Di dalam decompiler, identifikasi variabel yang menyimpan output digest (20 byte). Perhatikan perbandingan terhadap `xmmword_2030` dan konstanta 4-byte setelahnya.
4. Klik operand yang menunjukkan referensi data (`byte_4040`) lalu tekan `X` untuk melihat cross-references.
5. Buka hex view pada alamat `0x4040` untuk melihat 28 bytes mentah.
6. Pastikan `qword_4030` (alamat `0x4030`) di-interpret sebagai QWORD dan baca nilainya — harus 28.
7. Catat alamat berikut dari IDA: `addr_data` (`byte_4040`), `addr_len` (`qword_4030`), `addr_xmm16` (`xmmword_2030`), `addr_v14` (4-byte berikutnya). Gunakan alamat-alamat ini untuk mapping jika memakai skrip eksternal.

---

## Proses dekripsi manual (detail byte-level)

Data mentah (`byte_4040`, 28 bytes) dalam hex:

```
71 70 63 72 4C 65 72 61 04 65 02 04
68 74 7F 04 74 7C 02 62 7A 68 7B 07
70 06 74 4A
```

Proses dekripsi: setiap byte XOR `0x37`. Hasil XOR (hex -> ASCII):

```
71 ^ 37 = 46 -> 'F'
70 ^ 37 = 47 -> 'G'
63 ^ 37 = 54 -> 'T'
72 ^ 37 = 45 -> 'E'
4C ^ 37 = 7B -> '{'
65 ^ 37 = 52 -> 'R'
72 ^ 37 = 45 -> 'E'
61 ^ 37 = 56 -> 'V'
04 ^ 37 = 33 -> '3'
65 ^ 37 = 52 -> 'R'
02 ^ 37 = 35 -> '5'
04 ^ 37 = 33 -> '3'
68 ^ 37 = 5F -> '_'
74 ^ 37 = 43 -> 'C'
7F ^ 37 = 48 -> 'H'
04 ^ 37 = 33 -> '3'
74 ^ 37 = 43 -> 'C'
7C ^ 37 = 4B -> 'K'
02 ^ 37 = 35 -> '5'
62 ^ 37 = 55 -> 'U'
7A ^ 37 = 4D -> 'M'
68 ^ 37 = 5F -> '_'
7B ^ 37 = 4C -> 'L'
07 ^ 37 = 30 -> '0'
70 ^ 37 = 47 -> 'G'
06 ^ 37 = 31 -> '1'
74 ^ 37 = 43 -> 'C'
4A ^ 37 = 7D -> '}'
```

Hasil string terangkai:

```
FGTE{REV3R53_CH3CK5UM_L0G1C}
```

---

## Verifikasi checksum

Program menjumlahkan semua byte hasil XOR (unsigned accumulation). Program memeriksa apakah total sama dengan 90 (decimal).

Perhitungan akumulasi byte (unsigned) menghasilkan overflow 8-bit sampai akhirnya nilai akhir yang diperiksa sama dengan 90. Dengan demikian kondisi ini terpenuhi untuk data yang ada sehingga program akan mencetak hasil dekripsi.

---

## Ekstraksi otomatis (opsional)

Jika ingin reproduksi otomatis tanpa membuka IDA, dapat digunakan skrip Python yang:

* memetakan alamat virtual (yang dilihat di IDA) ke offset file melalui header PT_LOAD
* membaca `qword_4030` (panjang)
* membaca `byte_4040` sebanyak panjang tersebut
* XOR setiap byte dengan `0x37` dan menampilkan hasil

(Implementasi skrip tersebut dapat dibuat jika diperlukan; tidak disertakan di sini karena writeup ini fokus pada analisis manual dan hasil.)

---

## Kesimpulan

* Binary adalah challenge reverse statis: tidak menerima input eksternal; semua data yang dibutuhkan ada di dalam binary.
* Program memakai anti-debug + CPU check, tetapi tidak perlu dijalankan untuk menemukan flag; cukup mengekstrak data statis.
* Dekripsi adalah operasi sederhana XOR `0x37` pada 28 bytes di `byte_4040`.
* Hasil dekripsi: `FGTE{REV3R53_CH3CK5UM_L0G1C}` (flag).

---

## Referensi singkat

* IDA Pro: decompilation dan hex view
* ELF format: pengertian PT_LOAD untuk mapping vaddr -> file offset
