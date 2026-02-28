https://gemini.google.com/share/94f96167161a
````markdown
# Write-Up CTF: The Captain's Last Message

**Kategori:** Kriptografi
**Poin:** 500

---

## 📄 Ringkasan Tantangan

Tantangan ini mengharuskan kita untuk mendekripsi sebuah pesan rahasia yang berasal dari transmisi radio sebuah U-Boat Jerman pada era Perang Dunia II. File yang diberikan adalah sebuah file audio (`.wav`) yang berisi sinyal Morse. Setelah didekode, pesan Morse tersebut ternyata dienkripsi lebih lanjut menggunakan mesin Enigma. Tujuan utamanya adalah menemukan pengaturan (setting) Enigma yang benar untuk mengungkap pesan asli dan menemukan flagnya.

---

## 🛠️ Langkah-langkah Pengerjaan

### Langkah 1: Analisis File Audio dan Dekode Morse

Langkah pertama adalah menganalisis file `radio_silence_1943.wav`. Dengan menggunakan alat decoder audio Morse online atau tool sejenisnya, kita dapat menerjemahkan sinyal *beep* menjadi teks.

* **File:** `radio_silence_1943.wav`
* **Metode:** Audio Morse Code Decoder
* **Hasil Ciphertext:**
    ```
    XUMBUGVSGHCOGVIANUMOGQMMWESMPQDIUWELYXDKEYNTQUNPANJIDHBMYLOQINLRYFJVD SENAIYTGRQSRSOLVOCXKRRAIPUKGJRZETDJQZVSCSNFTCKJBNMBDJUOOLHPRZMWYGN
    ```

### Langkah 2: Analisis Petunjuk untuk Menentukan Setting Enigma

Ciphertext di atas dienkripsi menggunakan Enigma. Kita harus memecahkan serangkaian petunjuk dari deskripsi tantangan untuk menemukan konfigurasi yang tepat.

1.  **Plugboard (Steckerbrett):**
    * **Petunjuk:** `AVBS CGDL FUHZ INKM OWRX`
    * **Analisis:** Format ini secara jelas menunjukkan 10 pasang huruf yang dihubungkan di plugboard.
    * **Pengaturan:** `AV BS CG DL FU HZ IN KM OW RX`

2.  **Rotors (Walzenlage):**
    * **Petunjuk:** "...berasal dari kapal selam U-Boat 245..."
    * **Analisis:** Nomor `245` pada U-Boat adalah petunjuk langsung untuk rotor yang digunakan, yaitu **Rotor II, Rotor IV, dan Rotor V**. Urutan pemasukan yang benar pada simulator (`II IV V`) ditemukan melalui proses percobaan.
    * **Pengaturan:** `II IV V`

3.  **Reflector (Umkehrwalze):**
    * **Petunjuk:** "Operator komunikasi dikenal sangat menyukai simetri."
    * **Analisis:** Komponen Enigma yang paling identik dengan sifat simetri (jika A -> B, maka B -> A) adalah Reflector. Reflector standar yang paling umum adalah UKW B.
    * **Pengaturan:** `UKW B`

4.  **Initial Position (Grundstellung):**
    * **Petunjuk:** Di bagian atas halaman radio tertulis: `“CQ DE QST”`
    * **Analisis:** Dalam prosedur radio militer, tiga huruf terakhir dari header (setelah `CQ DE`) sering digunakan sebagai kunci pesan atau posisi awal rotor untuk transmisi tersebut.
    * **Pengaturan:** `Q S T`

5.  **Ring Settings (Ringstellung):**
    * **Petunjuk:** "Kapal berlayar pada hari ke-7..." dan petunjuk tersembunyi lainnya.
    * **Analisis:** Ini adalah bagian tersulit yang memerlukan beberapa kali percobaan.
        * **Ring 1:** Berasal dari "hari ke-7", sehingga nilainya adalah `7` (G).
        * **Ring 2 & 3:** Ditemukan melalui proses eliminasi dan denumerasi dari petunjuk lain, nilai yang benar adalah `3` (C) dan `11` (K).
    * **Pengaturan:** `07 03 11` (G C K)

### Langkah 3: Konfigurasi Final Mesin Enigma

Setelah menganalisis semua petunjuk, berikut adalah tabel konfigurasi lengkap dan final yang digunakan untuk mendekripsi pesan.

| Komponen             | Pengaturan Final                  |
| -------------------- | --------------------------------- |
| **Model** | Enigma M3 / I                     |
| **Reflector** | `UKW B`                           |
| **Rotors** | `II IV V`                         |
| **Ring Settings** | `07 03 11` (G C K)                |
| **Initial Position** | `Q S T`                           |
| **Plugboard** | `AV BS CG DL FU HZ IN KM OW RX`   |

### Langkah 4: Dekripsi Pesan dan Penemuan Flag

Dengan memasukkan semua pengaturan yang benar ke simulator Enigma, ciphertext berhasil didekripsi menjadi plaintext yang sedikit acak.

* **Plaintext Mentah:**
    ```
    thefl eetha srend ezvou sedat theus ualpo intal phame etsvi ctora tcawn allsy stems arsgr eenan dmora leish ighpr epare forth enext opera tionf gteal phame tvict or
    ```

* **Pesan yang Telah Diperbaiki:**
    Setelah spasinya diatur ulang, pesan menjadi lebih jelas:
    `the fleet has rendezvoused at the usual point alpha meets victor at cawn all systems are green and morale is high prepare for the next operation...`

* **Penemuan Flag:**
    Pada akhirnya, flag yang benar ditemukan, sesuai dengan konfirmasi Anda.

---

## 🚩 Flag

````

FGTE{alphametvictor}

```
```
