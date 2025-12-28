import os
import random
from flask import Flask, request
from Crypto.Util.number import long_to_bytes

app = Flask(__name__, static_url_path="")

FLAG = os.environ["FLAG"].encode()


def xor(a: bytes, b: bytes) -> bytes:
	"""XOR two byte strings"""
	return bytes(x ^ y for x, y in zip(a, b))

@app.route("/api/dh_exchange/", methods=["GET", "POST"])
def get_encrypted_message():
	try:
		p = int(request.json["p"])
		g = int(request.json["g"])
		A = int(request.json["A"])

		b = random.randint(1, p) # Bob's private
		B = pow(g, b, p) # Bob's public

		k = pow(A, b, p) # Shared key

		enc_flag = xor(FLAG, long_to_bytes(k))
		return {"enc_flag": enc_flag.hex(), "B": B}
	except Exception as e:
		return {"error": str(e)}
