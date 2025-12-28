https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 1 (Manual Exploitation)

## Informasi Tantangan

* **Nama Challenge:** Crypto 1
* **Kategori:** Cryptography
* **Metode:** Manual Exploitation (Web Tools)
* **Poin:** 500

## Deskripsi & Analisis

Tantangan ini menggunakan enkripsi **AES-CTR**. Celah keamanannya adalah **Nonce Reuse**. Server menggunakan Key dan Nonce yang sama berulang kali (selama server tidak di-restart).

Dalam AES-CTR:


Karena Keystream statis (akibat Nonce tetap), kita bisa melakukan serangan **Known Plaintext Attack**:

1. Kirim input panjang untuk mengetahui bentuk Plaintext awal.
2. Hitung: .
3. Gunakan Keystream tersebut untuk mendekripsi Ciphertext dari request lain (yang memuat flag).

Berikut adalah langkah penyelesaian manual menggunakan *tools* yang tersedia di website challenge.

---

## Langkah Penyelesaian

### 1. Dapatkan Ciphertext Panjang (Keystream Recovery)

Kita mengirimkan input username yang panjang (50 karakter 'A') untuk memancing keystream yang cukup panjang.

* **Tool:** `INTERACT`
* **Input Username:**
```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```


* **Output (JSON):**
```json
{"nonce":"b0d4877f658d267f","token":"e36bb2df5df4c544b16cc856b02afd20f45f70bb519604cedd386b1668ff9ae8d9a48588a5890db410b823d26ee7121c7dff32f5ff750ea1ee5606cf528fbcba513480d0922345b0450eb265ab7de8d03eb5ea81954efe341fbc4e0a9aa83d"}

```


> **Catatan:** Simpan token di atas sebagai **Ciphertext 1**. Perhatikan Nonce-nya adalah `b0d4877f658d267f`.



### 2. Siapkan Known Plaintext

Kita menyusun string JSON yang seharusnya terbentuk di sisi server berdasarkan input kita.

* **Format:** `{"user": "<50_A>", "flag": "`
* **Tool:** `HEX ENCODER/DECODER`
* **Ascii Here:**
```text
{"user": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "flag": "

```


* **Output (Hex Here):**
```text
7b2275736572223a20224141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c2022666c6167223a2022

```


> Simpan ini sebagai **Known Plaintext Hex**.



### 3. Ekstrak Keystream

Lakukan operasi XOR untuk mendapatkan Keystream.

* **Tool:** `XOR TOOL`
* **Input 0:** Ciphertext 1 (Token dari Langkah 1)
* **Input 1:** Known Plaintext Hex (Dari Langkah 2)
* **Output (Keystream):**
```text
9849c7ac3886e77e914e8917f16bbc61b51e31fa10d7458f9c792a5729bedba998e5c4c9e4c84cf551f962932fa6535d3cbe73b4be344fe0af17478e70a39c983758e1b7b0196592

```



### 4. Dapatkan Ciphertext Target (Flag)

Kirim input username pendek. Posisi flag akan maju ke depan dan terkena enkripsi oleh keystream yang sudah kita ketahui.

* **Tool:** `INTERACT`
* **Input Username:**
```text
a

```


* **Output (JSON):**
```json
{"nonce":"b0d4877f658d267f","token":"e36bb2df5df4c544b16ce835dd4b9e07d97f56d82af767dbce2d513618dbbf99a1d0a1aad1ad2dc634ca55ee0ddb"}

```


> **PENTING:** Pastikan **nonce** pada output ini (`b0d4877f658d267f`) SAMA PERSIS dengan langkah 1. Jika berbeda, ulangi request sampai sama.
> Simpan token ini sebagai **Ciphertext 2**.



### 5. Dekripsi Manual

Gunakan Keystream yang didapat di Langkah 3 untuk mendekripsi Ciphertext 2.

* **Tool:** `XOR TOOL`
* **Input 0:** Keystream (Dari Langkah 3)
* **Input 1:** Ciphertext 2 (Token dari Langkah 4)
* **Output (Plaintext Hex):**
```text
7b2275736572223a202261222c2022666c6167223a20225452547b613165643039356563356561336533377d227d

```



### 6. Decoding Flag

Terjemahkan hasil dekripsi hex kembali ke teks ASCII.

* **Tool:** `HEX ENCODER/DECODER`
* **Hex Here:** (Output dari Langkah 5)
* **Ascii Here (Hasil Akhir):**
```json
{"user": "a", "flag": "TRT{a1ed095ec5ea3e37}"}

```



## Kesimpulan

Dengan memanfaatkan kerentanan penggunaan Nonce yang berulang, kita berhasil mendekripsi pesan secara manual tanpa perlu brute force key.

**Flag:** `TRT{a1ed095ec5ea3e37}`
