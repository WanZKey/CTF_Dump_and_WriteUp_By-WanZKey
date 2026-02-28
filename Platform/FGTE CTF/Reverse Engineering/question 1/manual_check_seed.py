# solver_quiz.py
import ctypes
import sys

def solve_quiz(seed):
    """
    Mereplikasi logika pembuatan kuis dari binary untuk menghasilkan
    jawaban yang benar berdasarkan seed yang diberikan.
    """
    try:
        # Muat library C standar
        libc = ctypes.CDLL("libc.so.6")
    except OSError:
        print("[!] Error: Tidak dapat menemukan 'libc.so.6'. Skrip ini untuk Linux.")
        return

    # Atur tipe argumen dan return value untuk konsistensi
    libc.srand.argtypes = [ctypes.c_uint]
    libc.rand.restype = ctypes.c_int

    # Inisialisasi generator angka acak dengan seed dari program
    libc.srand(seed)

    print(f"[*] Menghasilkan jawaban untuk Seed: {seed}")
    print("---------------------------------------")

    answers = []
    for i in range(10):
        # Replikasi logika dari Ghidra
        a = libc.rand() % 100 + 1
        b = libc.rand() % 50 + 1
        op = libc.rand() % 4

        correct_answer = 0
        op_char = ''
        if op == 0:
            correct_answer = a + b
            op_char = '+'
        elif op == 1:
            correct_answer = a - b
            op_char = '-'
        elif op == 2:
            correct_answer = a * b
            op_char = '*'
        elif op == 3:
            correct_answer = a % b
            op_char = '%'
        
        print(f"Q{i+1}: {a} {op_char} {b} = {correct_answer}")
        answers.append(correct_answer)
    
    print("---------------------------------------")
    print("✅ Semua jawaban berhasil dibuat. Masukkan angka-angka di atas ke program.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Penggunaan: python3 {sys.argv[0]} <seed>")
        print(f"Contoh: python3 {sys.argv[0]} 1759076574")
    else:
        try:
            input_seed = int(sys.argv[1])
            solve_quiz(input_seed)
        except ValueError:
            print("[!] Error: Seed harus berupa angka.")
