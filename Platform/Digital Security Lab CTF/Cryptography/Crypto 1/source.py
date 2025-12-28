import os
from flask import Flask, request
import json
from Crypto.Cipher import AES

app = Flask(__name__, static_url_path="")

KEY = os.urandom(16)
NONCE = os.urandom(8)


@app.route("/api/get_encrypted_message/", methods=["GET", "POST"])
def get_encrypted_message():
	try:
		username = request.json["user"]
		token = json.dumps({"user": username, "flag": os.environ["FLAG"]})
		enc_token = AES.new(KEY, AES.MODE_CTR, nonce=NONCE).encrypt(token.encode())
		return {"token": enc_token.hex(), "nonce": NONCE.hex()}
	except Exception as e:
		return {"error": str(e)}
