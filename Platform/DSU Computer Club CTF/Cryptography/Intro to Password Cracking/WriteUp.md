```markdown
# Writeup: Intro to Password Cracking - DSU CTF

## Informasi Tantangan
* **Event:** DSU CTF
* **Kategori:** Cryptography / Password Cracking
* **Poin:** 150
* **Author:** Jacob R.

## Deskripsi
Tantangan ini menuntut peserta untuk membedah struktur file zip bersarang (*nested zip*) yang terdiri dari beberapa lapisan keamanan yang berbeda, mulai dari *plaintext*, *dictionary attack*, *salting*, hingga analisis hash algoritma Whirlpool.

## Langkah Pengerjaan

### 1. Layer 0: Plaintext Password
File awal adalah `layer0.zip`. Deskripsi tantangan secara eksplisit memberikan password untuk lapisan pertama: *"Open the first layer with 'password'"*.

```bash
unzip -P password layer0.zip
# Extracting: layer1.zip, starter.docx

```

### 2. Layer 1: Basic Dictionary Attack

File `layer1.zip` terkunci. Petunjuk pada `starter.docx` mengindikasikan penggunaan password yang lemah. Kita menggunakan `john` dengan wordlist standar `rockyou.txt`.

```bash
zip2john layer1.zip > layer1.hash
john --wordlist=/usr/share/wordlists/rockyou.txt layer1.hash
# Password found: password
unzip -P password layer1.zip

```

### 3. Layer 2: Dictionary Attack (Lanjut)

File `layer2.zip` juga terkunci. Metode yang sama digunakan kembali.

```bash
zip2john layer2.zip > layer2.hash
john --wordlist=/usr/share/wordlists/rockyou.txt layer2.hash
# Password found: bigapple1
unzip -P bigapple1 layer2.zip

```

### 4. Layer 3: Salted Wordlist Attack

Pada `layer3.zip`, serangan standar gagal. File `secret.docx` memberikan petunjuk bahwa password memiliki *salt* berupa string `xpepperx` di bagian depan (*prefix*).

Kita memanipulasi wordlist `rockyou.txt` agar setiap kata diawali dengan `xpepperx`.

```bash
# Tambahkan prefix 'xpepperx' ke setiap baris wordlist
sed 's/^/xpepperx/' /usr/share/wordlists/rockyou.txt > salted_rockyou.txt

# Cracking
zip2john layer3.zip > layer3.hash
john --wordlist=salted_rockyou.txt layer3.hash
# Password found: xpepperxmariobros
unzip -P xpepperxmariobros layer3.zip

```

### 5. Layer 4: PDF Numeric Brute Force

File selanjutnya adalah `final_secret.pdf`. Dokumen `another_secret.docx` memberikan petunjuk: *"This next password is just 8 random digits"*.

Untuk efisiensi, digunakan `pdfcrack` dengan charset angka.

```bash
pdfcrack -f final_secret.pdf -n 8 -m 8 -c 0123456789
# Password found: 93827460

```

### 6. Final Puzzle: Whirlpool Hash

Setelah membuka PDF dengan password `93827460`, kita mendapatkan teks petunjuk:

> *"This password is an Animal Name with three random digits after it... I love tidal pools. Or hot pools. Or whirly pools."*
> Hash: `3f75894e75...`

Petunjuk "whirly pools" mengarah ke algoritma **Whirlpool**. Format password adalah `[NamaHewan][000-999]`.

**Solver:**
Kita membuat wordlist kustom dengan menggabungkan nama hewan dari `animals.txt` dengan 3 digit angka menggunakan script Bash, lalu mencari hash yang cocok.

```bash
# Generate Custom Wordlist
for animal in $(cat animals.txt); do 
    for i in {000..999}; do 
        echo "${animal}${i}"
    done
done > wordlist_final.txt

# Hasil Cracking (via script/manual check)
# Hash target cocok dengan: Clownfish873

```

## Flag

```
DSU{Clownfish873}

```

```

```
