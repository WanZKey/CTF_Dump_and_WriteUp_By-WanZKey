def rail_fence_decrypt(ciphertext, rails):
    # Buat pola zig-zag
    fence = [['\n' for _ in range(len(ciphertext))] for _ in range(rails)]
    rail = 0
    var = 1

    for i in range(len(ciphertext)):
        fence[rail][i] = '*'
        rail += var

        if rail == rails - 1 or rail == 0:
            var = -var

    index = 0
    for i in range(rails):
        for j in range(len(ciphertext)):
            if fence[i][j] == '*' and index < len(ciphertext):
                fence[i][j] = ciphertext[index]
                index += 1

    result = []
    rail = 0
    var = 1
    for i in range(len(ciphertext)):
        result.append(fence[rail][i])
        rail += var

        if rail == rails - 1 or rail == 0:
            var = -var

    return ''.join(result)


ciphertext = "Samddre··ath·dhf@_oesoere·ebun·yhot·no··oso·i·a·lr1rcm·iS·aruf·toibadhn·nadpikudynea{l_oeee·ch·oide·f·n·aoe·sae·aonbdhgo_so·rr.i·tYnl·s·tdot·xs·hdtyy'·.t·cfrlca·epeo·iufiyi.t·yaaf·.a.·ts··tn33}i·tvhr·.tooho···rlmwuI·h·e·iHshonppsoleaseecrtudIdet.·n·BtIpdheiorcihr·or·ovl·c··i·acn·t·su··ootr·:b3cesslyedheIath·"

rails = 10
plaintext = rail_fence_decrypt(ciphertext, rails)
print(plaintext)
