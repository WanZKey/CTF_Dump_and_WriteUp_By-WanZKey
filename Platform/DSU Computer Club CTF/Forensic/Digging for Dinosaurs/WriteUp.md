# DSU CTF 2025: Digging for Dinosaurs Writeup

**Category:** Forensics
**Points:** 125
**Author:** Jacob R.

## Deskripsi Challenge

> I made this image to show a nice collection of my favorite dinosaurs. It's pretty cool as it is, but legend says that if you dig around enough, you might be able to find my most favorite secret dinosaur hidden within, but only if you know where a *steg* might hide. Poke around, find the passkey, and dig out the secret dino to get the flag.

**Hint:** *i like to store my tool names in italics to help me spot them more easily*

## Langkah Pengerjaan

### 1. Analisis Awal

Berdasarkan deskripsi dan hint:

* Kata "steg" dicetak miring, mengindikasikan penggunaan tool **Steghide**.
* Instruksi "dig around, find the passkey" mengindikasikan bahwa password untuk ekstraksi tersimpan di dalam file itu sendiri sebagai string yang dapat dibaca.

File yang diberikan adalah gambar BMP standar:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Digging for Dinosaurs]
└─$ file dinos.bmp
dinos.bmp: PC bitmap, Windows 3.x format, 1440 x 1440 x 24, image size 6220800...

```

### 2. Mencari Passkey

Kita mencari string yang dapat dibaca (printable strings) di dalam file binary. Biasanya password disembunyikan di bagian akhir file.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Digging for Dinosaurs]
└─$ strings dinos.bmp | tail -n 5
vt~qu
nfyhhzi
Zk]M^PP^RQcRSeTRdSP`OM]LN[KN[KRYLMZJNYINYINYIMXHOZJU\MQ[NT]PT]PR[NU\OX_R\`T\`TaeYei]
lveU_NT`LQ[JOYHOYIJTDPZJW^OQ[KMZJS\OJSFAJ=DNACPB5D69J=;J<1@2APBP_QCRD8E79F8<I;?L><I;6C54A37D6>H;DNAJTGKUHKUHKUHKUHISFGQDJTGMWJNYILVIHQDBL?@I<@M?AK;;E84>10:-/9,2</5?24=02</2</2</3=04>14>14>13=12<03=17A58B64>20:./9-1:04;45>44=35=37?45>43<22:06<14<23;119/08.19/3;138/05,,1(,1(.3*16-38/19/.6,05,27.5:18=4:?69>57<349016-/4+27.8<6:B8=B9;@76<16<16<15;05;04:/39.39.4:/38/19/39.39.39./8..6+*2'*4(+5)+5),4),4)+3(*2')1&+3(06+39.4:/36-28-.7*+3((2&'/$'/$+1&.4)37,59-04)26+2:06<13;02://9-/9-28-17,17,17,29,39.59.48-67-26+45+12)43)76,+*
OhGoodThingYouFoundThisCuzItsThePasswordIUsedForSteghide

```

Ditemukan passphrase yang sangat jelas di baris terakhir:
`OhGoodThingYouFoundThisCuzItsThePasswordIUsedForSteghide`

### 3. Ekstraksi Data

Menggunakan tool `steghide` dan passphrase yang telah ditemukan untuk mengekstrak data tersembunyi.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Digging for Dinosaurs]
└─$ steghide extract -sf dinos.bmp -p OhGoodThingYouFoundThisCuzItsThePasswordIUsedForSteghide
wrote extracted data to "secret_stegosaurus.jpg".

```

### 4. Hasil

File berhasil diekstrak menjadi `secret_stegosaurus.jpg`. Saat gambar tersebut dibuka, terdapat tulisan flag di dalamnya.

## Flag

`DSU{st3gos4urus_is_my_fav_d1no}`
