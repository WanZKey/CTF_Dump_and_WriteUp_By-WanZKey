#!/usr/bin/env python3
#!/usr/bin/env python3
from collections import deque

def solve_pda():
    with open("flag_checker.txt", "r") as f:
        # FIX: Hapus karakter \r dari setiap baris agar stack tidak kotor
        lines = [line.replace('\r', '') for line in f.read().splitlines()]

    init_line = lines[0]
    start_state = init_line[0]
    start_stack_sym = init_line[1]
    accept_states = init_line[2:]

    transitions = []
    for line in lines[1:]:
        if len(line) < 4:
            continue
        cur_state = line[0]
        input_char = line[1]
        pop_char = line[2]
        next_state = line[3]
        push_str = line[4:]
        transitions.append((cur_state, input_char, pop_char, next_state, push_str))

    # Queue menyimpan tuple: (state, stack_sebagai_tuple, string_flag)
    # Stack dijadikan tuple agar hemat memori
    queue = deque([(start_state, (start_stack_sym,), "")])

    while queue:
        state, stack, input_str = queue.popleft()
        
        if not stack:
            continue

        for (cs, ic, st, ns, pc) in transitions:
            # Jika state dan karakter teratas stack cocok
            if cs == state and st == stack[-1]:
                # Copy stack dan pop elemen terakhir
                new_stack = list(stack[:-1])
                
                # Push karakter baru secara terbalik
                for c in reversed(pc):
                    new_stack.append(c)
                
                # Cek kondisi menang: input adalah EOF '^' dan next state valid
                if ic == '^' and ns in accept_states:
                    return input_str
                # Jika bukan EOF, masukkan state baru ke antrean BFS
                elif ic != '^':
                    queue.append((ns, tuple(new_stack), input_str + ic))

    return "Flag not found"

if __name__ == "__main__":
    flag = solve_pda()
    print(f"Decrypted Flag: {flag}")
