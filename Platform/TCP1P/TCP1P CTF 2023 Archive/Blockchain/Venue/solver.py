from web3 import Web3

# GUNAKAN PUBLIC RPC (Gratis & Aktif)
# Jika satu gagal, coba ganti dengan yang lain di list
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com" 
# Alternatif lain: "https://rpc.sepolia.org" atau "https://1rpc.io/sepolia"

def solve():
    # 1. Setup Koneksi
    print(f"[*] Connecting to {rpc_url}...")
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        print("[-] Gagal konek ke Public RPC. Cek internet/VPN.")
        return
    print("[+] Connected successfully!")

    # 2. Setup Target Contract
    target_address = "0x1AC90AFd478F30f2D617b3Cb76ee00Dd73A9E4d3"
    target_address = w3.to_checksum_address(target_address)

    # ABI Minimal (Hanya fungsi enterVenue)
    contract_abi = [
        {
            "inputs": [],
            "name": "enterVenue",
            "outputs": [{"internalType": "string", "name": "", "type": "string"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]

    # 3. Load Contract
    contract = w3.eth.contract(address=target_address, abi=contract_abi)

    # 4. Panggil Fungsi (Call)
    print("[*] Calling enterVenue()...")
    try:
        flag = contract.functions.enterVenue().call()
        print(f"\n[+] FLAG FOUND: {flag}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
