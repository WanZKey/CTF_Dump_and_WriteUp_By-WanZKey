https://gemini.google.com/share/e11c4a5bfa65
---

# Writeup: Disguised Nameserver Smuggling

**CTF:** DSU CTF

**Category:** Forensics

**Points:** 175

**Author:** Jacob R.

## Deskripsi Tantangan

> "We think someone got access to this laptop and set up a rogue server to exfiltrate a flag using a common, often harmless protocol. They really tried to make it blend in, but I'm not sure they did a very good job. Here's a packet capture we managed to get our hands on. Can you figure out what they stole?"

## 1. Identifikasi Awal (Reconnaissance)

Langkah pertama adalah menganalisis file `exfil.pcap` yang diberikan. Berdasarkan informasi metadata:

* **File Type:** PCAP capture file (version 2.4).
* **Capture Length:** 65535.

Saat membuka file di Wireshark, tampilan awal didominasi oleh trafik **TCP** dan **HTTP** yang menuju ke `example.com`. Terlihat banyak request `GET / HTTP/1.1`. Namun, setelah menelusuri stream tersebut, isinya terlihat seperti *junk traffic* atau *decoy* (pengalih perhatian) karena hanya mengembalikan "OK" berulang kali.

Mengingat judul tantangan adalah **"Disguised Nameserver Smuggling"**, fokus analisis dialihkan dari TCP ke protokol **DNS** (Nameserver).

## 2. Analisis Trafik DNS (The Anomaly)

Dengan mengganti filter Wireshark menjadi `dns`, ditemukan pola lalu lintas yang mencurigakan:

1. Banyak DNS Query bertipe `A` record.
2. Domain tujuan memiliki pola tetap: `[HEX_DATA].challenge.roguedns.serverstation`.
3. Query dilakukan berulang-ulang dengan subdomain heksadesimal yang berubah-ubah (contoh: `54686973`, `20746861`).

Ini adalah indikasi kuat adanya serangan **DNS Tunneling** atau **DNS Exfiltration**, di mana data rahasia (flag) dipecah, di-encode ke dalam Hex, dan diselundupkan sebagai subdomain agar lolos dari firewall standar.

## 3. Ekstraksi Data (Scripting)

Untuk menyusun kembali pesan asli, kita perlu:

1. Mengambil semua nama domain dari paket DNS Query.
2. Mengambil bagian subdomain (chunk heksadesimal).
3. Membuang duplikat (karena retransmisi jaringan).
4. Menggabungkan heksadesimal tersebut.
5. Melakukan decoding dari Hex ke ASCII.

Saya menggunakan script Python `scrap-dns-rogue.py` dengan library `scapy` untuk melakukan otomatisasi ini.

### Eksekusi Script & Output Terminal

Berikut adalah hasil eksekusi script pada terminal Kali Linux:

```text
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Disguised Nameserver Smuggling]
└─$ python3 scrap-dns-rogue.py
Reading PCAP and extracting Hex chunks...
[+] Found chunk: 54686973
[+] Found chunk: 20697320
[+] Found chunk: 61207365
[+] Found chunk: 63726574
[+] Found chunk: 206d6573
[+] Found chunk: 73616765
[+] Found chunk: 20746861
[+] Found chunk: 74207468
[+] Found chunk: 65207065
[+] Found chunk: 72736f6e
[+] Found chunk: 20657866
[+] Found chunk: 696c7472
[+] Found chunk: 61746564
[+] Found chunk: 2e204974
[+] Found chunk: 2773206c
[+] Found chunk: 696b652c
[+] Found chunk: 20726561
[+] Found chunk: 6c6c7920
[+] Found chunk: 6c6f6e67
[+] Found chunk: 2e204920
[+] Found chunk: 616d2061
[+] Found chunk: 6464696e
[+] Found chunk: 67207468
[+] Found chunk: 69732074
[+] Found chunk: 6f20656e
[+] Found chunk: 636f7572
[+] Found chunk: 61676520
[+] Found chunk: 796f7520
[+] Found chunk: 746f2075
[+] Found chunk: 73652074
[+] Found chunk: 73686172
[+] Found chunk: 6b206f72
[+] Found chunk: 20626173
[+] Found chunk: 68206f72
[+] Found chunk: 20736f6d
[+] Found chunk: 65746869
[+] Found chunk: 6e672074
[+] Found chunk: 6f206865
[+] Found chunk: 6c702079
[+] Found chunk: 6f752065
[+] Found chunk: 78747261
[+] Found chunk: 63742074
[+] Found chunk: 68652068
[+] Found chunk: 65782e20
[+] Found chunk: 416e7977
[+] Found chunk: 61792c20
[+] Found chunk: 68657265
[+] Found chunk: 27732079
[+] Found chunk: 6f757220
[+] Found chunk: 666c6167
[+] Found chunk: 3a204453
[+] Found chunk: 557b6974
[+] Found chunk: 735f6869
[+] Found chunk: 64696e67
[+] Found chunk: 5f66726f
[+] Found chunk: 6d5f796f
[+] Found chunk: 755f696e
[+] Found chunk: 5f706c61
[+] Found chunk: 696e5f73
[+] Found chunk: 69676874
[+] Found chunk: 7d204920
[+] Found chunk: 616d2061
[+] Found chunk: 6c736f20
[+] Found chunk: 61646469
[+] Found chunk: 6e672074
[+] Found chunk: 68697320
[+] Found chunk: 70616464
[+] Found chunk: 696e6720
[+] Found chunk: 73656e74
[+] Found chunk: 656e6365
[+] Found chunk: 2e205468
[+] Found chunk: 616e6b20
[+] Found chunk: 796f7520
[+] Found chunk: 666f7220
[+] Found chunk: 6c697374
[+] Found chunk: 656e696e
[+] Found chunk: 672e

[!] Full Hex Stream: 54686973206973206120736563726574206d65737361676520746861742074686520706572736f6e20657866696c7472617465642e2049742773206c696b652c207265616c6c79206c6f6e672e204920616d20616464696e67207468697320746f20656e636f757261676520796f7520746f207573652074736861726b206f722062617368206f7220736f6d657468696e6720746f2068656c7020796f75206578747261637420746865206865782e20416e797761792c2068657265277320796f757220666c61673a204453557b6974735f686964696e675f66726f6d5f796f755f696e5f706c61696e5f73696768747d204920616d20616c736f20616464696e6720746869732070616464696e672073656e74656e63652e205468616e6b20796f7520666f72206c697374656e696e672e

[🎉] FLAG FOUND:
This is a secret message that the person exfiltrated. It's like, really long. I am adding this to encourage you to use tshark or bash or something to help you extract the hex. Anyway, here's your flag: DSU{its_hiding_from_you_in_plain_sight} I am also adding this padding sentence. Thank you for listening.

```

## 4. Kesimpulan & Flag

Pesan yang didecode berisi sebuah kalimat panjang yang menyembunyikan flag di dalamnya. Penyerang menggunakan metode ini untuk menyembunyikan "harta karun" di tempat terbuka (*in plain sight*), mengandalkan fakta bahwa volume traffic DNS seringkali diabaikan.

**Flag:**

```
DSU{its_hiding_from_you_in_plain_sight}

```
