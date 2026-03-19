#!/usr/bin/env python3
import numpy as np
import random
import string
import sys

WIDTH = 10
HEIGHT = 5
PALETTE = ".:-=+*#%@oT0w&8R"
CHARSET = string.ascii_letters + string.digits + "_"

def solve():
    # 1. Parsing gambar target dari file art_flag.txt
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

    # 2. Persiapan pemetaan kombinasi 'steps' dan 'stroke'
    steps_to_chars = {s: [] for s in range(3, 8)}
    for c in CHARSET:
        byte = ord(c)
        steps, stroke = divmod(byte, len(PALETTE))
        if 3 <= steps <= 7:
            steps_to_chars[steps].append((c, stroke))
            
    # Karakter yang sudah diketahui (T, F, {, dan })
    known_sequence = [
        (ord('T') // 16, ord('T') % 16),
        (ord('F') // 16, ord('F') % 16),
        (ord('{') // 16, ord('{') % 16)
    ]
    known_end = (ord('}') // 16, ord('}') % 16)

    # Inisialisasi awal PRNG
    initial_pos = np.array([HEIGHT // 2, WIDTH // 2])
    initial_used = {tuple(initial_pos)}
    rng = random.Random(b"VuwC")

    # Fungsi untuk memvalidasi stroke/karakter setelah path ditemukan
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
                        return # Jalur gagal menutupi area yang dibutuhkan
                        
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
    
    # Fungsi DFS untuk mengeksplorasi path
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
                
            # PRUNING: Jika mendarat di area yang seharusnya kosong, skip
            if target_image[curr_pos[0], curr_pos[1]] == -1:
                continue
                
            new_r_state = r.getstate()
            new_steps_hist = steps_hist + [s]
            new_pos_hist = pos_hist + [tuple(curr_pos)]
            
            dfs(idx + 1, curr_pos, curr_used, new_r_state, new_steps_hist, new_pos_hist)

    dfs(0, initial_pos, initial_used, rng.getstate(), [], [])
    print("[!] Proses selesai. Jika tidak ada flag, cek kembali logika pencarian.")

if __name__ == '__main__':
    solve()
