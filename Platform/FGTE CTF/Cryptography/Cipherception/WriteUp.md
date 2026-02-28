https://gemini.google.com/share/66a32f125274
```markdown
# Write-up CTF: Cipherception

## 📝 Deskripsi Challenge

| Keterangan | Detail |
| :--- | :--- |
| **Nama Challenge** | Cipherception |
| **Kategori** | Cryptography |
| **Kesulitan** | Easy |
| **Author** | aria |
| **Deskripsi** | Pesan ini sudah dienkripsi dengan metode klasik, tapi sepertinya seseorang memodifikasinya lagi dengan cara yang tidak biasa. |

---

## 🧐 Analisis Awal

Tantangan ini menyajikan sebuah ciphertext yang terdiri dari huruf kapital, angka, dan beberapa simbol. Deskripsi "metode klasik" yang "dimodifikasi" mengarahkan kita untuk mencurigai cipher substitusi. Kehadiran angka dan simbol yang tercampur langsung di dalam kata-kata (contoh: `F10K`, `U6Q4-F(MD`) adalah petunjuk utama bahwa ini adalah **Simple Substitution Cipher** di mana alfabet standar (A-Z) telah diperluas untuk mencakup karakter-karakter non-alfabetik tersebut.

Tujuan utama kita adalah merekonstruksi tabel substitusi (kunci) untuk mendekripsi pesan dan menemukan flag.

---

## 🛠️ Langkah-langkah Pengerjaan

Metode yang paling efektif di sini adalah kombinasi dari *Known-Plaintext Attack* (menggunakan format flag sebagai petunjuk) dan analisis pola kata untuk menemukan kunci substitusi secara bertahap.

### Langkah 1: Mengidentifikasi Petunjuk Kunci (Crib)

Di akhir ciphertext, terdapat sebuah string yang sangat mirip dengan format flag terenkripsi:
```

34F({6J(MHF06Q\_Q041F3HUU\_30QHU\_M(J6MF\_K(PVM(}

```
Kita juga diberitahu bahwa format flag yang benar adalah `FGTE{...}`. Dengan membandingkan kedua string ini, kita dapat melakukan *Known-Plaintext Attack* untuk mendapatkan pemetaan kunci awal.

`34F({`  ➡️  `FGTE{`

Dari sini, kita mendapatkan pemetaan berikut:
* `3` ➡️ `F`
* `4` ➡️ `G`
* `F` ➡️ `T`
* `(` ➡️ `E`

Ini adalah penemuan krusial, terutama karena kita mengetahui bahwa sebuah simbol (`(`) memetakan ke sebuah huruf (`E`), yang mengkonfirmasi teori "modifikasi yang tidak biasa".

### Langkah 2: Analisis Pola Kata untuk Memperluas Kunci

Dengan kunci awal di tangan, kita dapat mulai mendekripsi bagian lain dari teks.
Kata pertama dari ciphertext adalah `F10K`. Mengingat ini adalah awal kalimat, kata yang paling mungkin dalam bahasa Inggris adalah "THIS". Mari kita gunakan asumsi ini.

`F10K` ➡️ `THIS`

Ini memberikan kita pemetaan kunci baru:
* `1` ➡️ `H`
* `0` ➡️ `I`
* `K` ➡️ `S`

### Langkah 3: Rekonstruksi Tabel Substitusi

Sekarang, kita gabungkan semua pemetaan yang telah kita temukan dan menerapkannya pada ciphertext untuk mengungkap lebih banyak kata dan huruf.

**Tabel Substitusi (Berkembang):**

| Cipher | Plain | Keterangan |
| :---: | :---: | :--- |
| `3` | `F` | Dari format flag |
| `4` | `G` | Dari format flag |
| `F` | `T` | Dari format flag |
| `(` | `E` | Dari format flag |
| `1` | `H` | Dari asumsi `F10K` -> `THIS` |
| `0` | `I` | Dari asumsi `F10K` -> `THIS` |
| `K` | `S` | Dari asumsi `F10K` -> `THIS` |

Mari kita terapkan pada kata kedua, `FMHQKD0KK06Q`:
* **Cipher**: `F M H Q K D 0 K K 0 6 Q`
* **Parsial**: `T M H Q S D I S S I 6 Q`

Kata ini sangat mirip dengan "TRANSMISSION". Jika benar, kita mendapatkan:
* `M` ➡️ `R`
* `H` ➡️ `A` (*Tunggu, ini kontradiksi. Mari kita cek lagi*).

**Koreksi:** Kata satu huruf `H` di dalam teks kemungkinan besar adalah `A`. Mari kita gunakan pemetaan ini. `H` -> `A`.
Sekarang kita ulangi pada `FMHQKD0KK06Q`:
* **Cipher**: `F M H Q K D 0 K K 0 6 Q`
* **Parsial**: `T M A Q S D I S S I 6 Q`
Kata ini jelas `TRANSMISSION`. Maka:
* `M` ➡️ `R`, `Q` ➡️ `N`, `D` ➡️ `M`, `6` ➡️ `O`.

Dengan proses yang sama, kita bisa memecahkan kata-kata lain:
* `JHMF` (`J A R T`) ➡️ `PART` ➡️ `J` ➡️ `P`
* `(W(MP0K(` (`E W E R P I S E`) ➡️ `EXERCISE` ➡️ `W` ➡️ `X`, `P` ➡️ `C`
* `U6Q4-F(MD` (`U O N G - T E R M`) ➡️ `LONG-TERM` ➡️ `U` ➡️ `L`

Kita terus melanjutkan proses ini hingga sebagian besar kunci terungkap.

### Langkah 4: Dekripsi Flag

Dengan tabel substitusi yang sudah cukup lengkap, kita dapat kembali ke string flag terenkripsi untuk mengungkap isinya.

* **Cipher Flag**: `34F({6J(MHF06Q_Q041F3HUU_30QHU_M(J6MF_K(PVM(}`
* **Dekripsi Prefiks**: `34F({` ➡️ `FGTE{`

Mari kita dekripsi bagian intinya:
1.  `6J(MHF06Q` ➡️ `OPERATION`
2.  `Q041F3HUU` ➡️ `NIGHTFALL`
3.  `30QHU` ➡️ `FINAL`
4.  `M(J6MF` ➡️ `REPORT`
5.  `K(PVM(` ➡️ `SECURE` (Ini memberikan kita pemetaan terakhir yang penting, `V` ➡️ `U`)

Setelah digabungkan, kita mendapatkan flag yang utuh.

---

## 🏁 Flag

```

FGTE{OPERATION\_NIGHTFALL\_FINAL\_REPORT\_SECURE}

```
```
