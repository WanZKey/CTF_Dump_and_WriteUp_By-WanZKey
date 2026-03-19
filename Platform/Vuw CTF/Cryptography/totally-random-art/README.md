# WriteUp - totally-random-art

## Overview
- **Judul Challenge:** totally-random-art
- **Kategori:** Cryptography
- **Poin:** 300
- **Author:** maxster
- **Release:** VuwCTF 2025
- **Solves:** 0
- **First Blood:** krauq (krauq)
- **Deskripsi:** VuwCTF suspects that this random art generator used to decorate top-secret documents was being used to leak sensitive information. Can you find the original flag? The body of the flag contains only `[a-zA-Z0-9_]`.

## Informasi Attachment & Struktur Direktori
Terdapat dua file utama, yaitu `randart.py` sebagai *source code* *generator* dan `art_flag.txt` yang berisi *output* ASCII art dari *flag* asli. Berikut adalah inspeksi awal direktori dan isi file:

```bash
…WanZKey  ～  ~../Cryptography/totally-random-art 󱎫 0s 󱑎 06.23
 󰋑  ▶  tree
.
├── art_flag.txt
└── randart.py

1 directory, 2 files

…WanZKey  ～  ~../Cryptography/totally-random-art 󱎫 0s 󱑎 06.23
 󰋑  ▶  cat art_flag.txt
+-----18-----+
| +@+ +&     |
|     .  +-  |
|        8   |
|        + @ |
|          R |
+-----18-----+
```

*Source code* `randart.py` menunjukkan mekanisme *random walk* di atas kanvas `10x5` (*WIDTH* x *HEIGHT*) menggunakan palet 16 karakter `.:-=+*#%@oT0w&8R`.

## Proses Penyelesaian
1. **Analisis PRNG Seed & Known Plaintext:** Modul `random` diinisialisasi menggunakan 4 *byte* pertama dari data input (`random.Random(data[0:4])`). Karena kita tahu format standar adalah `VuwCTF{...}`, maka *seed* PRNG sudah pasti adalah `VuwC`.
2. **Analisis Panjang Data:** Bingkai ASCII art `+-----18-----+` membocorkan informasi bahwa panjang *flag* adalah 18 karakter. Dikurangi 4 karakter awal sebagai *seed*, tersisa 14 karakter yang akan diiterasi untuk menggambar. Dari 14 karakter ini, kita tahu 3 karakter pertama adalah `T`, `F`, `{`, dan karakter terakhir adalah `}`. Tersisa 10 karakter *body* yang dibatasi pada rentang `[a-zA-Z0-9_]`.
3. **Analisis Mekanisme Menggambar (Divmod):** Setiap *byte* (karakter) dipecah menjadi `steps` dan `stroke` melalui operasi `steps, stroke = divmod(byte, 16)`.
   - `steps` (`byte // 16`) menentukan **berapa kali** kursor bergerak secara acak. Karena pergerakan (*direction*) diambil dari `rng.choice()`, maka rute pergerakan **sepenuhnya bergantung pada nilai `steps`**.
   - `stroke` (`byte % 16`) menentukan "warna" (indeks dari `PALETTE`) yang ditambahkan pada posisi mendarat terakhir.
4. **Optimasi Pruning Ekstrim:** Kanvas awalnya diisi penuh dengan spasi. Berdasarkan file `art_flag.txt`, hanya ada sedikit titik kordinat yang terisi karakter. Jika pada iterasi *brute-force* kursor mendarat di kordinat yang pada `art_flag.txt` adalah spasi kosong, maka jalur tersebut dipastikan salah dan bisa langsung diabaikan (*pruned*).
5. **Implementasi Depth-First Search (DFS):** Menyusun *script solver* yang menyimulasikan *state* PRNG dan menelusuri (*brute-force*) semua kombinasi `steps` yang mungkin untuk karakter alfanumerik (berkisar antara 3 hingga 7). Jika rute valid (*landing* pada kordinat berkarakter), langkah dilanjutkan.
6. **Validasi Stroke Akhir:** Setelah 14 karakter rute ditemukan, *script* mencocokkan total nilai `stroke` yang tertumpuk di setiap kordinat agar sesuai dengan indeks karakter palet pada `art_flag.txt`. Kombinasi `steps` dan `stroke` yang cocok akan direkonstruksi kembali menjadi *flag* utuh.

## Script Solver
**solver.py**
```python
import numpy as np
import random
import string
import sys

WIDTH = 10
HEIGHT = 5
PALETTE = ".:-=+*#%@oT0w&8R"
CHARSET = string.ascii_letters + string.digits + "_"

def solve():
    try:
        with open("art_flag.txt", "r") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        print("[!] File art_flag.txt tidak ditemukan.")
        return

    target_image = np.full((HEIGHT, WIDTH), -1, dtype=int)
    for r in range(HEIGHT):
        row_str = lines[r+1][2:WIDTH+2]
        row_str = row_str.ljust(WIDTH, " ")
        for c in range(WIDTH):
            char = row_str[c]
            if char in PALETTE:
                target_image[r, c] = PALETTE.index(char)

    steps_to_chars = {s: [] for s in range(3, 8)}
    for c in CHARSET:
        byte = ord(c)
        steps, stroke = divmod(byte, len(PALETTE))
        if 3 <= steps <= 7:
            steps_to_chars[steps].append((c, stroke))
            
    known_sequence = [
        (ord('T') // 16, ord('T') % 16),
        (ord('F') // 16, ord('F') % 16),
        (ord('{') // 16, ord('{') % 16)
    ]
    known_end = (ord('}') // 16, ord('}') % 16)

    initial_pos = np.array([HEIGHT // 2, WIDTH // 2])
    initial_used = {tuple(initial_pos)}
    rng = random.Random(b"VuwC")

    def check_strokes(steps_hist, pos_hist):
        pos_to_indices = {}
        for i, p in enumerate(pos_hist):
            if p not in pos_to_indices:
                pos_to_indices[p] = []
            pos_to_indices[p].append(i)
            
        for r in range(HEIGHT):
            for c in range(WIDTH):
                if target_image[r, c] != -1:
                    if (r, c) not in pos_to_indices:
                        return 
                        
        strokes = [0] * 14
        strokes[0] = known_sequence[0][1]
        strokes[1] = known_sequence[1][1]
        strokes[2] = known_sequence[2][1]
        strokes[13] = known_end[1]
        
        positions_to_satisfy = list(pos_to_indices.keys())
        valid_strokes_for_idx = {}
        for idx in range(3, 13):
            s = steps_hist[idx]
            valid_strokes_for_idx[idx] = [stroke for (char, stroke) in steps_to_chars[s]]
            
        valid_strokes_for_idx[0] = [strokes[0]]
        valid_strokes_for_idx[1] = [strokes[1]]
        valid_strokes_for_idx[2] = [strokes[2]]
        valid_strokes_for_idx[13] = [strokes[13]]
        
        def solve_position(p_idx, current_strokes):
            if p_idx == len(positions_to_satisfy):
                flag_body = ""
                for i in range(3, 13):
                    s = steps_hist[i]
                    stroke = current_strokes[i]
                    char = chr(s * 16 + stroke)
                    flag_body += char
                print(f"\n[*] CRACKED! Flag : VuwCTF{{{flag_body}}}")
                sys.exit(0)
                
            p = positions_to_satisfy[p_idx]
            indices = pos_to_indices[p]
            target = target_image[p[0], p[1]]
            
            def pick_stroke_for_indices(idx_in_indices, current_sum):
                if idx_in_indices == len(indices):
                    if current_sum % 16 == target:
                        solve_position(p_idx + 1, current_strokes)
                    return
                    
                real_idx = indices[idx_in_indices]
                for stroke in valid_strokes_for_idx[real_idx]:
                    current_strokes[real_idx] = stroke
                    pick_stroke_for_indices(idx_in_indices + 1, current_sum + stroke)
                    
            pick_stroke_for_indices(0, 0)
            
        solve_position(0, [0]*14)

    print("[*] Melakukan penelusuran DFS (Brute-force path)...")
    
    def dfs(idx, pos, used, r_state, steps_hist, pos_hist):
        if idx == 14:
            check_strokes(steps_hist, pos_hist)
            return
            
        if idx == 0:
            candidates = [known_sequence[0][0]]
        elif idx == 1:
            candidates = [known_sequence[1][0]]
        elif idx == 2:
            candidates = [known_sequence[2][0]]
        elif idx == 13:
            candidates = [known_end[0]]
        else:
            candidates = [3, 4, 5, 6, 7]
            
        for s in candidates:
            r = random.Random()
            r.setstate(r_state)
            
            curr_pos = np.copy(pos)
            curr_used = used.copy()
            
            for i in range(s):
                direction = r.choice([(1,0), (-1,0), (0,1), (0,-1), (1,1), (1,-1), (-1,1), (-1,-1)])
                curr_pos += np.array(direction)
                if tuple(curr_pos) not in curr_used:
                    curr_used.add(tuple(curr_pos))
                else:
                    direction = r.choice([(1,0), (-1,0), (0,1), (0,-1), (1,1), (1,-1), (-1,1), (-1,-1)])
                    curr_pos += np.array(direction)
                    curr_used.add(tuple(curr_pos))
                curr_pos[0] %= HEIGHT
                curr_pos[1] %= WIDTH
                
            if target_image[curr_pos[0], curr_pos[1]] == -1:
                continue
                
            new_r_state = r.getstate()
            new_steps_hist = steps_hist + [s]
            new_pos_hist = pos_hist + [tuple(curr_pos)]
            
            dfs(idx + 1, curr_pos, curr_used, new_r_state, new_steps_hist, new_pos_hist)

    dfs(0, initial_pos, initial_used, rng.getstate(), [], [])

if __name__ == '__main__':
    solve()
```

## Output Terminal
```bash
 󰋑  ▶  ./solver.py
[*] Melakukan penelusuran DFS (Brute-force path)...

[*] CRACKED! Flag : VuwCTF{r4nd0M_4RT}
```

## Flag

```
VuwCTF{r4nd0M_4RT}
```
