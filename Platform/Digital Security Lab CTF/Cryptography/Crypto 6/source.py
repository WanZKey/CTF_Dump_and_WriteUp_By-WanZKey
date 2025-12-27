import os
from flask import Flask, request
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA


app = Flask(__name__, static_url_path="")

with open("rsa_key.pem", "r") as f:
	KEY = RSA.import_key(f.read())
FLAG = os.environ["FLAG"].encode()

flag_enc = pow(bytes_to_long(FLAG), KEY.e, KEY.n)


@app.route("/api/get_params/", methods=["GET", "POST"])
def get_params():
	return {"enc_flag": flag_enc, "n": KEY.n, "e": KEY.e}

@app.route("/api/rsa_decrypt/", methods=["GET", "POST"])
def rsa_decrypt():
	try:
		ct = int(request.json["ct"])
		# check that it doesn't decrypt to the flag
		if ct < 0 or ct > KEY.n or ct == flag_enc:
			raise ValueError("Invalid ciphertext")
		
		pt = pow(ct, KEY.d, KEY.n)
		return {"pt": pt}
	except Exception as e:
		return {"error": str(e)}
