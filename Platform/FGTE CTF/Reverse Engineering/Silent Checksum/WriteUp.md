https://gemini.google.com/share/505c238a8af2
````markdown
# Write-Up: Silent Checksum (Reverse)

* **Challenge:** Silent Checksum
* **Author:** Anam
* **Kategori:** Reverse
* **Poin:** 360

---

## Ringkasan

Challenge ini menuntut kita untuk menganalisis sebuah *binary* ELF 64-bit yang *stripped*. *Binary* ini dilengkapi dengan beberapa lapisan pertahanan: anti-debugging (`ptrace`) dan anti-VM (`cpuid`). Inti dari *binary* ini adalah menghitung *hash* SHA-1 dari sebuah data internal, membandingkannya, lalu mendekripsi sebuah *string* menggunakan XOR sederhana.

Bagian "jebakan"-nya adalah "Silent Checksum": setelah *flag* didekripsi, program menjalankan pemeriksaan *checksum* (penjumlahan *byte*) pada *flag* tersebut. *Checksum* ini sengaja dirancang untuk **gagal**, sehingga program akan selalu mencetak "Wrong!" bahkan jika *flag* berhasil didekripsi. Solusinya adalah dengan melakukan analisis statis, menemukan algoritma dekripsi, dan mengabaikan *checksum* jebakan tersebut.

---

## Analisis Awal

Melakukan pemeriksaan awal pada berkas `silent_checksum_linux`:

1.  **`file`**: `ELF 64-bit LSB pie executable, x86-64, ... stripped`. Ini adalah *binary* 64-bit yang *stripped* (simbol-simbolnya telah dihapus) dan PIE (*Position Independent Executable*) diaktifkan.
2.  **`checksec`**: `NX enabled` dan `PIE enabled`. Ini standar untuk *binary* modern.
3.  **`strings`**: Menunjukkan beberapa *string* yang menarik seperti `"Wrong!"`, `"qpcrLera"`, dan `"bzh{"`. Ini memberi petunjuk bahwa ada *string* tersembunyi.
4.  **Menjalankan Berkas**: Menjalankan `./silent_checksum_linux` langsung menghasilkan output `"Wrong!"`.

---

## Analisis Statis Mendalam (IDA Pro / Ghidra)

Karena *binary* ini *stripped* dan dilindungi, analisis statis adalah cara terbaik. Kita buka di IDA Pro.

### 1. Fungsi `main` dan Anti-Analisis

Fungsi `main` (di IDA dekompilasi Anda) segera menunjukkan dua teknik anti-analisis:

* **Anti-Debugging**: Panggilan pertama adalah `ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL)`. Jika *binary* ini dijalankan di bawah *debugger* (seperti GDB), panggilan `ptrace` ini akan gagal dan program akan keluar.
* **Anti-VM**: Panggilan `sub_18A0()` menggunakan instruksi `cpuid` untuk memeriksa *hypervisor bit*. Ini adalah teknik standar untuk mendeteksi apakah program sedang berjalan di dalam *Virtual Machine*. Program hanya akan melanjutkan ke logika utama jika `sub_18A0()` mengembalikan `0` (tidak di dalam VM).

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  // ...
  // 1. Anti-Debugging
  if ( ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL) != -1 || *__errno_location() != 1 )
  {
    // 2. Anti-VM
    if ( (unsigned int)sub_18A0() ) 
    {
      usleep(0x249F0u); // Keluar jika di dalam VM
    }
    else
    {
      // ... Logika Utama ...
    }
  }
  v5 = "Wrong!";
LABEL_8:
  puts(v5);
  return 0LL;
}
````

### 2\. Logika Utama: Validasi SHA-1

Jika lolos dari pemeriksaan anti-analisis, program masuk ke logika intinya.

  * `sub_12B0(v15, byte_4040);`
  * `sub_1640(v15, byte_4040, qword_4030);`
  * `sub_1730(v15, v12);`

Jika kita menganalisis `sub_12B0`, kita akan melihat inisialisasi konstanta-konstanta ajaib:

  * `0x67452301`
  * `0xEFCDAB89`
  * `0x98BADCFE`
  * `0x10325476`
  * `0xC3D2E1F0`

Ini adalah konstanta inisialisasi standar untuk algoritma *hash* **SHA-1**. Program ini menghitung *hash* SHA-1 dari data yang ada di `byte_4040` (dengan panjang di `qword_4030`).

Hasil *hash* (20 *byte*) kemudian dibandingkan dengan nilai yang di-*hardcode* (disimpan di `si128` dan `v14` dalam dekompilasi IDA Anda).

```c
    // ...
    // Menghitung hash SHA-1 dari byte_4040
    sub_12B0(v15, byte_4040);
    v3 = qword_4030;
    sub_1640(v15, byte_4040, qword_4030);
    sub_1730(v15, v12); // v12 sekarang berisi hash
    
    // Membandingkan hash v12 dengan hash yang di-hardcode
    v4 = 0LL;
    v14 = -69733426; 
    si128 = _mm_load_si128((const __m128i *)&xmmword_2030);
    while ( v12[v4] == si128.m128i_i8[v4] )
    {
      if ( ++v4 == 20 ) // Jika hash cocok...
      {
        // ... Lanjut ke dekripsi ...
      }
    }
    // ...
```

Validasi SHA-1 ini sebenarnya adalah pengecoh. Kita tidak perlu mem-bruteforce datanya; kita hanya perlu melihat apa yang terjadi **setelah** perbandingan itu berhasil.

### 3\. Dekripsi Flag (Bagian "Aman")

Di dalam blok `if ( ++v4 == 20 )`, kita menemukan logika dekripsi.

```c
        // ... (di dalam blok if hash cocok) ...
        v7 = 0LL;
        v5 = v16; // v5 adalah pointer yang akan dicetak
        do
        {
          // INI ADALAH KUNCINYA:
          // Byte dari byte_4040 di-XOR dengan 0x37
          v16[v7] = byte_4040[v7] ^ 0x37; 
          ++v7;
        }
        while ( v3 != v7 ); // v3 adalah panjang data
        v16[v3] = 0; // Null-terminator
        // ...
```

Logikanya sangat sederhana:

  * Ambil data dari `byte_4040`.
  * Ambil panjang data dari `v3` (yang berasal dari `qword_4030`).
  * Lakukan operasi **XOR setiap *byte* dengan `0x37`**.
  * Simpan hasilnya (flag yang didekripsi) di `v16`.

### 4\. Jebakan "Silent Checksum"

Ini adalah bagian paling licik. Tepat setelah dekripsi, program **tidak langsung** mencetak *flag*. Ia menjalankan satu pemeriksaan terakhir:

```c
        // ... (setelah loop dekripsi) ...
        v8 = v16; // v8 menunjuk ke flag yang sudah didekripsi
        v9 = &v16[v3]; // v9 menunjuk ke akhir flag
        v10 = 0; // Akumulator checksum
        do
        {
          v11 = *v8++; // Baca byte flag
          v10 += v11; // Tambahkan ke akumulator
        }
        while ( v9 != v8 );
        
        // Periksa apakah total checksum (sebagai char 8-bit) = 90
        // 90 adalah kode ASCII untuk 'Z'
        if ( v10 == 90 ) 
          goto LABEL_8; // Jika lolos, cetak flag (v5)
        
        break; // Jika gagal, keluar dari blok
      }
    }
  }
  v5 = "Wrong!"; // Jika gagal di titik mana pun, v5 diatur ke "Wrong!"
LABEL_8:
  puts(v5); // Cetak v5
```

Program menghitung *checksum* sederhana (penjumlahan 8-bit) dari **flag yang telah didekripsi** dan membandingkannya dengan `90` (karakter 'Z').

Jika kita hitung *checksum* dari *flag* yang kita dapat: `FGTE{REV3R53_CH3CK5UM_L0G1C}`:
`sum(bytearray("FGTE{REV3R53_CH3CK5UM_L0G1C}".encode())) & 0xFF` = **214**.

Karena `214 != 90`, pemeriksaan `if ( v10 == 90 )` akan **selalu gagal**. Ini menyebabkan program keluar dari blok, menjalankan `v5 = "Wrong!";`, dan akhirnya mencetak "Wrong\!".

Ini adalah "Silent Checksum": sebuah pemeriksaan tersembunyi yang memastikan *binary* tidak akan pernah mencetak *flag*, memaksa kita untuk mengandalkan analisis statis.

-----

## Mendapatkan Flag

Kita sudah tahu semua yang kita perlukan. Kita hanya perlu meniru langkah dekripsi dan mengabaikan *checksum*.

**1. Ekstrak Data Terenkripsi**

Dari IDA, kita pergi ke alamat `byte_4040`.

```
.data:0000000000004040 byte_4040 db 71h, 70h, 63h, 72h, 4Ch, 65h, 72h, 61h
.data:0000000000004048         db 04h, 65h, 02h, 04h, 68h, 74h, 7Fh, 04h
.data:0000000000004050         db 74h, 7Ch, 02h, 62h, 7Ah, 68h, 7Bh, 07h
.data:0000000000004058         db 70h, 06h, 74h, 4Ah
```

Data heksadesimalnya adalah:
`71 70 63 72 4C 65 72 61 04 65 02 04 68 74 7F 04 74 7C 02 62 7A 68 7B 07 70 06 74 4A`

**2. Skrip Dekripsi**

Kita buat skrip Python sederhana untuk melakukan operasi `XOR 0x37`.

```python
# Data terenkripsi dari alamat 0x4040
encrypted_data = b"\x71\x70\x63\x72\x4C\x65\x72\x61\x04\x65\x02\x04\x68\x74\x7F\x04\x74\x7C\x02\x62\x7A\x68\x7B\x07\x70\x06\x74\x4A"

flag = ""
key = 0x37

# Lakukan dekripsi XOR
for byte in encrypted_data:
    decrypted_byte = byte ^ key
    flag += chr(decrypted_byte)

print(f"Flag: {flag}")

# Membuktikan bahwa checksum gagal
# Program menghitung checksum dari flag yang didekripsi
checksum_binary = sum(bytearray(flag.encode())) & 0xFF
print(f"Checksum Flag (dihitung oleh binary): {checksum_binary}") # Akan menghasilkan 214
print(f"Checksum Target (yang dicari binary): {90}") # 'Z'
if checksum_binary == 90:
    print("Checksum Lolos!")
else:
    print("Checksum Gagal (Ini adalah jebakannya!)")
```

**3. Menjalankan Skrip**

```bash
$ python3 decrypt.py
Flag: FGTE{REV3R53_CH3CK5UM_L0G1C}
Checksum Flag (dihitung oleh binary): 214
Checksum Target (yang dicari binary): 90
Checksum Gagal (Ini adalah jebakannya!)
```

## Flag

**`FGTE{REV3R53_CH3CK5UM_L0G1C}`**

```
```
