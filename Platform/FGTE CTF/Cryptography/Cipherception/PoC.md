Tentu, mari kita pecahkan tantangan kriptografi "Cipherception" ini bersama-sama.

### 🕵️ Analisis Awal

Berdasarkan deskripsi, *challenge* ini menggunakan metode enkripsi klasik yang dimodifikasi. Ciphertext berisi huruf kapital, angka, dan beberapa simbol yang tercampur dalam kata-kata. Ini adalah petunjuk kuat bahwa kita berhadapan dengan **Simple Substitution Cipher** (Cipher Substitusi Sederhana) di mana alfabetnya telah diperluas untuk mencakup angka dan simbol, bukan hanya huruf.

Tugas kita adalah membangun kembali tabel substitusi (kunci) untuk mendekripsi pesannya.

-----

### 🔑 Proses Dekripsi

Langkah-langkah untuk memecahkan cipher ini adalah dengan menggunakan *Known-Plaintext Attack* dan analisis pola kata.

#### 1\. Menggunakan Format Flag sebagai Petunjuk Awal (Crib)

Kita diberikan format flag `FGTE{...}` dan di akhir ciphertext terdapat string yang mirip dengan flag terenkripsi:
`34F({6J(MHF06Q_Q041F3HUU_30QHU_M(J6MF_K(PVM(}`

Kita bisa berasumsi bahwa `34F(` adalah bentuk terenkripsi dari `FGTE{`. Dari sini kita mendapatkan pemetaan kunci pertama kita:

  * `3` ➡️ `F`
  * `4` ➡️ `G`
  * `F` ➡️ `T`
  * `(` ➡️ `E` (simbol `(` ternyata memetakan ke huruf `E`\!)

#### 2\. Menebak Kata Pertama

Kata pertama dari ciphertext adalah `F10K`. Dalam bahasa Inggris, kata empat huruf yang sangat umum di awal kalimat adalah "THIS". Mari kita coba asumsi ini:

  * `F10K` ➡️ `THIS`

Ini memberikan kita pemetaan tambahan:

  * `1` ➡️ `H`
  * `0` ➡️ `I`
  * `K` ➡️ `S`

#### 3\. Memperluas Kunci dengan Konteks

Sekarang, mari kita gabungkan semua kunci yang telah kita temukan dan terapkan pada beberapa kata pertama dari ciphertext untuk menemukan lebih banyak pemetaan.

  * **Cipher**: `F10K FMHQKD0KK06Q 0K JHMF 63 H`
  * **Plaintext (parsial)**: `THIS TRA...ISSIO. IS PART OF A`

Dari sini, kita bisa melengkapi kata-kata yang umum:

  * `FMHQKD0KK06Q` ➡️ `TRANSMISSION`
      * `M` ➡️ `R`, `Q` ➡️ `N`, `D` ➡️ `M`, `6` ➡️ `O`
  * `JHMF` ➡️ `PART`
      * `J` ➡️ `P`
  * `63` ➡️ `OF` (konsisten dengan `6` ➡️ `O` dan `3` ➡️ `F`)
  * `H` adalah kata satu huruf, yang kemungkinan besar adalah `A`.
      * `H` ➡️ `A`

Dengan melanjutkan proses ini ke seluruh ciphertext, kita dapat membangun tabel substitusi yang hampir lengkap.

-----

### 🏁 Menemukan Flag

Setelah kita memiliki kunci yang cukup, kita bisa langsung mendekripsi bagian flag dari ciphertext.

  * **Cipher Flag**: `34F({6J(MHF06Q_Q041F3HUU_30QHU_M(J6MF_K(PVM(}`

Mari kita gunakan kunci yang telah kita temukan untuk mendekripsinya bagian per bagian:

| Ciphertext | Plaintext | Kunci yang Digunakan |
| :--- | :--- | :--- |
| `34F(` | `FGTE{` | `3`→`F`, `4`→`G`, `F`→`T`, `(`→`E`, `{`→`{` |
| `6J(MHF06Q` | `OPERATION` | `6`→`O`, `J`→`P`, `(`→`E`, `M`→`R`, `H`→`A`, `F`→`T`, `0`→`I`, `Q`→`N` |
| `Q041F3HUU` | `NIGHTFALL` | `Q`→`N`, `0`→`I`, `4`→`G`, `1`→`H`, `F`→`T`, `3`→`F`, `H`→`A`, `U`→`L` |
| `30QHU` | `FINAL` | `3`→`F`, `0`→`I`, `Q`→`N`, `H`→`A`, `U`→`L` |
| `M(J6MF` | `REPORT` | `M`→`R`, `(`→`E`, `J`→`P`, `6`→`O`, `F`→`T` |
| `K(PVM(` | `SECURE` | `K`→`S`, `(`→`E`, `P`→`C`, `V`→`U`, `M`→`R` |

Dengan menggabungkan semua bagian yang telah didekripsi, kita mendapatkan flag lengkapnya.

> **🚩 Flag:**
>
> ```
> FGTE{OPERATION_NIGHTFALL_FINAL_REPORT_SECURE}
> ```

Selamat\! Tantangan berhasil dipecahkan.

Apakah Anda ingin saya membantu mendekripsi seluruh isi pesan dari ciphertext tersebut?
