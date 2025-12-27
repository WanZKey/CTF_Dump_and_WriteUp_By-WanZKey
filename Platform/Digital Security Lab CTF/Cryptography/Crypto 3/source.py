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
		username = request.json["username"]
		if username == "admin":
			raise Exception("Invalid username")
		token = pad(json.dumps({"username": username, "access_time": time.time()}))
		enc_token = AES.new(KEY, AES.MODE_ECB).encrypt(token.encode())
		return {"token": enc_token.hex()}
	except Exception as e:
		return {"error": str(e)}

@app.route("/api/decrypt_message/", methods=["POST"])
def decrypt_message():
	try:
		enc_token = bytes.fromhex(request.json["token"])
		token = AES.new(KEY, AES.MODE_ECB).decrypt(enc_token)
		parsed = json.loads(token.decode())
		if time.time() - parsed["access_time"] > 60*60:
			raise Exception("Token expired")
		if parsed["username"] == "admin":
			return {"msg": "Welcome admin!", "flag": os.environ["FLAG"]}
		return {"msg": f"Welcome {parsed['username']}!"}
	except Exception as e:
		return {"error": str(e)}
