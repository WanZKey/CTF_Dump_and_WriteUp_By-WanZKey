# WriteUp - SI BOBBY ISTANA

## Overview

* **Name:** SI BOBBY ISTANA
* **Category:** Forensic
* **Point:** 130 PTS
* **Author:** -
* **Description:** Temukan nomor handphone tuan dari si Bobby. Flag format: `Zerosec(CTF_08xxxxxx)`

## Reconnaissance

File yang diberikan adalah ZIP archive berisi satu file JPEG.

**Struktur Direktori:**
```bash
.
└── Pi7_edited-620765387-295401085-ab80a44e-e09f-4526-ac99-e3b24918b224.jpeg
```

Recon awal dengan `exiftool` mengungkap beberapa field EXIF yang mencurigakan:

```bash
exiftool Pi7_edited-620765387-295401085-ab80a44e-e09f-4526-ac99-e3b24918b224.jpeg
```

Field penting yang ditemukan:
- **Make:** `"wihebat" and this is also strong`
- **Artist:** `"Joko" Is powerfull words`
- **UserComment:** String panjang berisi encoded emoji (base64)

Dari dua field tersebut, disimpulkan password/key adalah **"Jokowihebat"**.

UserComment setelah di-decode dari base64 menghasilkan deretan emoji cipher.

## Step by Step Solution

### 1. Ekstrak dan Analisis File JPEG

Unzip archive dan jalankan exiftool untuk melihat metadata EXIF.

```bash
unzip chall.zip
exiftool Pi7_edited-620765387-295401085-ab80a44e-e09f-4526-ac99-e3b24918b224.jpeg
```

Ditemukan field `Make` dan `Artist` yang mengandung kata **"Joko"** dan **"wihebat"**, membentuk key: `Jokowihebat`.

### 2. Decode UserComment dari Base64

Field `UserComment` berisi string base64 yang di-decode menghasilkan deretan emoji:

```
😫👪👷🙆👘👨😲👲👕👑👥👸👒😲👦👴🙉😸🙇👳🙂😷👘🙅👓😳😳🙆👔👢👺👤👺👕👱👑👱🙆👶👫👳👦😴👸👨👕👷👭👚🙈🙍😵👲👮
```

### 3. Decrypt Emoji Cipher dengan Key

Menggunakan tool **txtmoji.com** untuk decrypt emoji cipher dengan:
- **Ciphertext:** emoji string di atas
- **Key:** `Jokowihebat`

**Output:** `My username bangbangpotato92`

### 4. OSINT Username bangbangpotato92

Melakukan pencarian username `bangbangpotato92` di berbagai platform. Ditemukan profil Instagram:

```
instagram.com/bangbangpotato92
```

**Temuan di Bio Instagram:**

```
@t.me/082188435678 for transactions
```

Nomor HP tuan si Bobby ditemukan langsung di bio profil Instagram.

## Script Solver

Tidak diperlukan script otomatis — challenge ini diselesaikan secara manual via exiftool, base64 decode, emoji cipher decrypt (txtmoji.com), dan OSINT Instagram.

## Output Terminal Solver

```bash
$ exiftool Pi7_edited-620765387-295401085-ab80a44e-e09f-4526-ac99-e3b24918b224.jpeg
Make        : "wihebat" and this is also strong
Artist      : "Joko" Is powerfull words
UserComment : 8J+Yq/Cfkarwn5G38J+ZhvCf... (base64)

# base64 decode UserComment -> emoji ciphertext
# decrypt via txtmoji.com with key "Jokowihebat"
# output: My username bangbangpotato92

# OSINT -> instagram.com/bangbangpotato92
# Bio: @t.me/082188435678 for transactions
```

## Flag

```
Zerosec(CTF_082188435678)
```


