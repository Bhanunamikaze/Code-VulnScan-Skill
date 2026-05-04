# crypto-reviewer

Read this when auditing cryptographic implementations and key management.

## Goal

Find weak algorithm choices, broken cryptographic implementations, insecure key management, and insecure randomness usage that would allow an attacker to compromise confidentiality, integrity, or authenticity guarantees.

## Part 1: Algorithm selection

### Broken/weak hash algorithms

Flag any use of MD5, SHA1, or CRC for security purposes:

- Password storage with MD5/SHA1 → critical (preimage attacks, rainbow tables)
- Integrity checks using MD5/SHA1 → high (collision attacks)
- HMAC-MD5/HMAC-SHA1 for authentication → medium (length extension, collision concerns)

Safe alternatives: SHA-256, SHA-3, BLAKE2, BLAKE3 for general hashing. bcrypt, scrypt, Argon2id, PBKDF2 (≥310,000 iterations with SHA-256) for passwords.

```python
# Flag these
hashlib.md5(password.encode()).hexdigest()
hashlib.sha1(data).digest()
import md5; md5.new(data).hexdigest()

# Safe
import bcrypt; bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
from argon2 import PasswordHasher; ph = PasswordHasher(); ph.hash(password)
```

### Weak symmetric encryption

Flag:
- DES, 3DES (TDEA), RC4, RC2, Blowfish with small keys → broken/deprecated
- AES in ECB mode → deterministic, pattern-leaking → high
- AES in CBC mode without MAC authentication → malleable ciphertext → medium
- AES with keys < 128 bits
- Static IV / IV = 0 in CBC or CTR mode → high

Safe: AES-256-GCM, ChaCha20-Poly1305 (authenticated encryption with associated data).

```python
# Flag these
from Crypto.Cipher import DES, ARC4
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)             # ECB mode
cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16) # zero IV

# Safe
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, data, aad)
```

### Weak asymmetric encryption / key exchange

Flag:
- RSA keys < 2048 bits → high
- RSA with PKCS#1 v1.5 padding for encryption → PKCS#1 oracle attacks → high
- DSA with key sizes < 2048 bits
- Elliptic curves: NIST P-192, Brainpool P-160, secp112r1 — too small
- Custom DH group construction
- DH with groups < 2048 bits (LOGJAM)
- Use of `textbook RSA` (raw RSA without padding)

Safe: RSA-2048+ with OAEP padding, ECDSA/ECDH with P-256/P-384/X25519, Ed25519.

### TLS/SSL configuration

Flag:
- SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 enabled
- Weak cipher suites: RC4, DES, EXPORT, NULL, ANON ciphers
- `verify=False` or `ssl_verify=False` in HTTP client calls → critical (disables cert validation)
- `CERT_NONE` in Python ssl context
- Custom hostname verifier that always returns true (Java, Android)
- Self-signed certificate in production without pinning

```python
# Critical
requests.get(url, verify=False)
ssl_context.verify_mode = ssl.CERT_NONE

# Java/Android critical
TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] c, String a) {}  // does nothing
    public void checkServerTrusted(X509Certificate[] c, String a) {}  // does nothing
}};
```

## Part 2: Key and secret management

### Key generation

Flag:
- Cryptographic keys derived from low-entropy sources (timestamps, sequential numbers, user IDs)
- Hardcoded keys in source code — use `sub-skills/secret-detector.md` for systematic detection
- Keys stored in plaintext files committed to the repository
- Environment variables used for keys without documentation (not wrong, but flag for review)
- Short keys: AES < 128 bits, RSA < 2048 bits, ECDSA < 224 bits, HMAC < 128 bits

```python
# Flag: key derived from timestamp
key = hashlib.sha256(str(int(time.time())).encode()).digest()

# Flag: hardcoded key
SECRET_KEY = "mysecretkey123"
JWT_SECRET = "abc123"
AES_KEY = b"0123456789abcdef"
```

### Key storage and rotation

- Keys stored in database tables — verify access controls
- Keys never rotated — note as informational if no mechanism exists
- Key derivation without salt (KDF without salt) → same input always produces same key
- KDF with too few iterations (PBKDF2 < 100,000 iterations for 2024)

### IV / nonce management

- IV reuse with same key in CBC/GCM → catastrophic in GCM (keystream recovery), significant in CBC
- Nonce counter overflow not handled in CTR/GCM mode
- IV derived from predictable value (timestamp, counter) in CBC where random IV is required
- GCM tag truncation below 96 bits

## Part 3: Insecure randomness

Any use of a non-cryptographically-secure PRNG for a security-sensitive purpose is a finding.

Security-sensitive purposes: token generation, session IDs, CSRF tokens, OTP codes, password reset tokens, nonces, salts, key generation, challenge-response.

**Flag in Python:**
```python
import random
random.random()           # not CSPRNG
random.randint(0, 999999) # predictable OTP
random.choice(chars)      # predictable token

# Safe
import secrets
secrets.token_hex(32)
secrets.token_urlsafe(32)
secrets.randbelow(1000000)
```

**Flag in JavaScript:**
```javascript
Math.random()             // not CSPRNG
Math.floor(Math.random() * 1000000)  // predictable OTP

// Safe (Node.js)
const crypto = require('crypto');
crypto.randomBytes(32).toString('hex');
crypto.randomInt(0, 1000000);

// Safe (browser)
window.crypto.getRandomValues(new Uint8Array(32));
```

**Flag in Java:**
```java
new Random().nextInt()    // not CSPRNG
// Safe:
SecureRandom sr = new SecureRandom();
byte[] bytes = new byte[32];
sr.nextBytes(bytes);
```

**Flag in PHP:**
```php
rand()                    // not CSPRNG
mt_rand()                 // not CSPRNG
// Safe:
random_bytes(32)
random_int(0, 999999)
```

## Part 4: Cryptographic protocol issues

### HMAC and MAC

- Using `==` to compare MACs → timing oracle → medium
  ```python
  # Flag
  if computed_mac == provided_mac:  # timing side channel
  # Safe
  import hmac; hmac.compare_digest(computed_mac, provided_mac)
  ```
- MAC computed after encryption without authentication (Encrypt-then-MAC vs MAC-then-Encrypt)
- HMAC key shorter than the hash output size

### Certificate and PKI

- Certificate expiry not monitored (note as operational finding)
- Certificate pinning not used for high-value mobile/API clients
- Self-signed certificates in non-development environments
- Wildcard certificates used where SAN-specific certs are warranted

### Cryptographic agility issues

- Algorithm negotiation allowing downgrade to weak options
- No version pinning in crypto negotiation headers

## Output format

```json
{
  "file": "app/utils/auth.py",
  "line": 27,
  "category": "weak_random",
  "title": "Insecure PRNG used for password reset token generation",
  "description": "random.choice() is used to generate a 6-character password reset token. This PRNG is not cryptographically secure and produces predictable output.",
  "evidence": "token = ''.join(random.choice(string.ascii_letters) for _ in range(6))",
  "impact": "An attacker can predict password reset tokens and take over accounts.",
  "remediation": "Use secrets.token_urlsafe(32) to generate a 256-bit cryptographically secure token.",
  "cwe": "CWE-338",
  "severity": "high"
}
```
