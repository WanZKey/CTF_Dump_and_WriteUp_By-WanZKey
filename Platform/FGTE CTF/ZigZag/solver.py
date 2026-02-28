ct = "FZAMBRYGEIZGIPEUTIKTGSLTC"

def rail_fence_decrypt(ct, rails):
    n = len(ct)
    rail_indices = [[] for _ in range(rails)]
    idx = 0
    direction = 1
    for i in range(n):
        rail_indices[idx].append(i)
        if rails > 1:
            idx += direction
            if idx == 0 or idx == rails - 1:
                direction *= -1
    res = [''] * n
    pos = 0
    for r in range(rails):
        for _ in rail_indices[r]:
            res[_] = ct[pos]
            pos += 1
    return ''.join(res)

print(rail_fence_decrypt(ct, 3))
