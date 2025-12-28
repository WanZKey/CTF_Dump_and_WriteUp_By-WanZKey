import os
import random
from flask import Flask, request
from Crypto.Util.number import long_to_bytes

app = Flask(__name__, static_url_path="")

FLAG = os.environ["FLAG"].encode()

G = 2
P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687

b = random.randint(1, P) # Bob's private



def xor(a: bytes, b: bytes) -> bytes:
	"""XOR two byte strings"""
	return bytes(x ^ y for x, y in zip(a, b))

"""Exchange flag with Charlie"""
# Charlie's public
C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771
k_c = pow(C, b, P) # Shared key with Charlie
msg_c = xor(FLAG, long_to_bytes(k_c)) # Message for Charlie
B_c = pow(G, b, P) # Bob's public for Charlie

@app.route("/api/dh_exchange/", methods=["GET", "POST"])
def get_encrypted_message():
	try:
		"""Exchange message with Alice (client)"""
		p = int(request.json["p"])
		g = int(request.json["g"])
		A = int(request.json["A"])

		B_a = pow(g, b, p) # Bob's public with Alice
		k_a = pow(A, b, p) # Shared key with Alice
		msg_a = xor(b"Hello Alice!", long_to_bytes(k_a)) # Message for Alice

		return {"msg_a": msg_a.hex(), "B_a": B_a, "msg_c": msg_c.hex(), "B_c": B_c}
	except Exception as e:
		return {"error": str(e)}
