import os
from flask import Flask, request
import json
from Crypto.Cipher import AES
import time

app = Flask(__name__, static_url_path="")

KEY = os.urandom(16)


def pad(s: str) -> str:
	"""Pad the message with spaces to be a multiple of 16 bytes"""
	return s + (16 - len(s) % 16) * " "

@app.route("/api/get_encrypted_message/", methods=["GET", "POST"])
def get_encrypted_message():
	try:
		username = request.json["user"]
		if username == "admin":
			raise Exception("Invalid username")
		token = pad(json.dumps({"user": username, "access_time": time.time()}))
		iv = os.urandom(16)
		enc_token = AES.new(KEY, AES.MODE_CBC, iv=iv).encrypt(token.encode())
		return {"token": enc_token.hex(), "iv": iv.hex()}
	except Exception as e:
		return {"error": str(e)}

@app.route("/api/decrypt_message/", methods=["POST"])
def decrypt_message():
	try:
		enc_token = bytes.fromhex(request.json["token"])
		iv = bytes.fromhex(request.json["iv"])
		token = AES.new(KEY, AES.MODE_CBC, iv=iv).decrypt(enc_token)
		parsed = json.loads(token.decode())
		if parsed["user"] == "admin":
			return {"msg": "Welcome admin!", "flag": os.environ["FLAG"]}
		return {"msg": f"Welcome {parsed['user']}!"}
	except Exception as e:
		return {"error": str(e)}
