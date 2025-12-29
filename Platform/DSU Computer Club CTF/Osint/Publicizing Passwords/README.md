# WriteUp: Publicizing Passwords

## Informasi Tantangan

* **Nama:** Publicizing Passwords
* **Kategori:** OSINT
* **Poin:** 50
* **Author:** iurii Chmykhun
* **Deskripsi:**
> It's never a good idea to enter your passwords when onlookers are watching. But what about entering iPhone PINs when recorded by cameras?
> What was Kanye's phone password in 2018?
> Format: `DSU{1234321}` (wrap the PIN in DSU{})



## Langkah Penyelesaian

### 1. Analisis Petunjuk

Deskripsi tantangan memberikan beberapa kata kunci penting:

* **Subject:** Kanye (West).
* **Object:** iPhone PIN / Password.
* **Year:** 2018.
* **Context:** "Recorded by cameras" (terekam kamera).

### 2. Pencarian Informasi (OSINT)

Langkah selanjutnya adalah mencari peristiwa spesifik di tahun 2018 di mana Kanye West terekam kamera sedang membuka kunci ponselnya.

**Query Pencarian:**

```text
Kanye West iPhone PIN 2018 camera

```

**Hasil Temuan:**
Banyak artikel berita dan video dari **Oktober 2018** yang melaporkan pertemuan Kanye West dengan Presiden Donald Trump di Oval Office (Gedung Putih).

* **Peristiwa:** Pada tanggal 11 Oktober 2018, saat pertemuan tersebut, Kanye West mengeluarkan iPhone X miliknya untuk menunjukkan gambar pesawat hidrogen (iPlane 1) kepada Trump.
* **Insiden Keamanan:** Kamera merekam momen saat Kanye mengetikkan passcode untuk membuka kunci ponselnya.
* **Passcode:** Terlihat jelas ia menekan angka nol berulang kali. Kodenya adalah **000000**.

### 3. Verifikasi

Video rekaman dari pertemuan tersebut (banyak tersedia di YouTube atau arsip berita seperti The Verge, BBC, dll) mengonfirmasi bahwa ia mengetikkan `0` sebanyak 6 kali.

### 4. Penyusunan Flag

Format yang diminta adalah `DSU{PIN}`.

* **PIN:** 000000

Maka flagnya adalah:
`DSU{000000}`

## Flag

```text
DSU{000000}

```
