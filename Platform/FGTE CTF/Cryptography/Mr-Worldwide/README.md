# WriteUp - Mr-Worldwide

## Overview

* **Judul:** Mr-Worldwide
* **Kategori:** Crypto / OSINT
* **Poin:** 100
* **Author:** aria
* **Deskripsi:**
Seorang musisi meninggalkan pesan untuk kita. Apa artinya?
(Kumpulan Koordinat GPS)
Format: FGTE{WORD_WORD}

## Informasi Attachment

Challenge ini memberikan serangkaian koordinat GPS yang terbagi menjadi dua kelompok.

**Koordinat:**

```text
(35.028309, 135.753082) (46.469391, 30.740883)
(39.758949, -84.191605) (41.015137, 28.979530)
(24.466667, 54.366669) (3.140853, 101.693207)
_
(9.005401, 38.763611) (-3.989038, -79.203560)
(52.377956, 4.897070) (41.085651, -73.858467)
(57.790001, -152.407227) (31.205753, 29.924526)

```

## Proses Penyelesaian

1. **Analisa Hint:**
Judul "Mr-Worldwide" merujuk pada penyanyi **Pitbull**. Ini adalah petunjuk untuk mencari lokasi geografis (OSINT) berdasarkan koordinat yang diberikan di seluruh dunia.
2. **Geolocation:**
Setiap koordinat dipetakan ke kota terdekat menggunakan Google Maps. Huruf pertama dari setiap kota diambil untuk membentuk pesan tersembunyi.
**Bagian 1:**
* `35.028309, 135.753082` -> **K**yoto, Jepang
* `46.469391, 30.740883` -> **O**desa, Ukraina
* `39.758949, -84.191605` -> **D**ayton, USA
* `41.015137, 28.979530` -> **I**stanbul, Turki
* `24.466667, 54.366669` -> **A**bu Dhabi, UAE
* `3.140853, 101.693207` -> **K**uala Lumpur, Malaysia
* **Hasil:** `KODIAK`


**Bagian 2:**
* `9.005401, 38.763611` -> **A**ddis Ababa, Ethiopia
* `-3.989038, -79.203560` -> **L**oja, Ecuador
* `52.377956, 4.897070` -> **A**msterdam, Belanda
* `41.085651, -73.858467` -> **S**leepy Hollow, USA
* `57.790001, -152.407227` -> **K**odiak, USA
* `31.205753, 29.924526` -> **A**lexandria, Mesir
* **Hasil:** `ALASKA`


3. **Assembly:**
Menggabungkan hasil dekode menjadi format flag yang diminta.

## Flag

```
FGTE{KODIAK_ALASKA}

```
