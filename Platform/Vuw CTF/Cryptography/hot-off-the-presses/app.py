import base64
import random
import time
from math import floor
from os import getenv

from Crypto.Util.Padding import pad
from flask import Flask, render_template, Response
from flask.cli import load_dotenv
from Crypto.Cipher import AES

load_dotenv()
FLAG = getenv("FLAG")

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.post('/news')
def news():
    seed = floor(time.time())

    random.seed(seed) # random encoding for secure download
    cipher = AES.new(random.randbytes(AES.block_size), AES.MODE_CBC, random.randbytes(AES.block_size))
    padded = pad(base64.b64encode(FLAG.encode('utf-8')), AES.block_size)

    ct = cipher.encrypt(padded)
    return Response(
        ct,
        mimetype='application/octet-stream',
        headers={
            "Content-Disposition": "attachment; filename=news.bin"
        }
    )


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=9898)