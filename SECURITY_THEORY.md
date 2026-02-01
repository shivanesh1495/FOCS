# 🔐 Security Theory Documentation
## 23CSE313 – Foundations of Cyber Security Lab

---

## §5.2 Security Levels & Risks

Our Secure File Sharing System implements **4 layers of defense-in-depth**:

### 🔹 Level 1: Authentication Layer
| Security Property | Implementation | Risk if Missing |
|-------------------|----------------|-----------------|
| Password Protection | bcrypt hashing with 10 rounds | Password exposure in database breach |
| Per-User Salt | Unique salt stored per user | Rainbow table attacks |
| Multi-Factor Auth | TOTP via Google Authenticator | Account takeover via stolen password |

**Why This Matters**: Even if passwords are leaked, attackers cannot use them without the TOTP device.

---

### 🔹 Level 2: Authorization Layer
| Security Property | Implementation | Risk if Missing |
|-------------------|----------------|-----------------|
| Role-Based Access | Admin/Owner/Viewer roles | Privilege escalation |
| Server-side Enforcement | JWT middleware checks | Bypass via URL manipulation |
| Principle of Least Privilege | Viewers can't upload | Data corruption/injection |

**Why This Matters**: A compromised Viewer account cannot modify files or escalate to Admin.

---

### 🔹 Level 3: Encryption Layer (Data Protection)
| Security Property | Implementation | Risk if Missing |
|-------------------|----------------|-----------------|
| Data at Rest | AES-256-CBC encryption | Data theft from storage |
| Key Exchange | RSA-2048 hybrid encryption | Key interception |
| No Plaintext Storage | Original file deleted after encryption | Direct file access |

**Why This Matters**: Even with database/storage access, encrypted files are unreadable without keys.

---

### 🔹 Level 4: Integrity Layer
| Security Property | Implementation | Risk if Missing |
|-------------------|----------------|-----------------|
| File Hashing | SHA-256 hash of original file | Undetected tampering |
| Digital Signatures | RSA-signed hash | Impersonation attacks |
| Verification on Download | Hash comparison | Downloading corrupted files |

**Why This Matters**: Users can trust downloaded files haven't been modified.

---

## §5.3 Possible Attacks & Countermeasures

### 🛡️ Attack/Defense Matrix

| Attack Type | Description | Our Defense | Code Reference |
|-------------|-------------|-------------|----------------|
| **Brute Force** | Guessing passwords repeatedly | bcrypt slow hashing (10 rounds = ~100ms/hash) slows attempts | `auth.js:30-31` |
| **Rainbow Table** | Pre-computed hash lookup | Unique salt per user makes pre-computation infeasible | `auth.js:30` |
| **Credential Stuffing** | Using leaked password lists | MFA requires physical device possession | `auth.js:111-116` |
| **Session Hijacking** | Stealing authentication tokens | JWT 1-hour expiry + MFA verification | `auth.js:85,126` |
| **Privilege Escalation** | Viewer trying Admin actions | Server-side role verification middleware | `files.js:26-31` |
| **Man-in-the-Middle** | Intercepting file transfers | AES key encrypted with RSA (only private key holder can decrypt) | `files.js:89` |
| **Data Tampering** | Modifying encrypted files | Digital signature verification fails on tamper | `files.js:178-188` |
| **Key Disclosure** | Hardcoded/weak keys | Keys generated dynamically using crypto.randomBytes() | `files.js:68` |
| **SQL/NoSQL Injection** | Malicious database queries | Mongoose ODM with schema validation | `models/User.js` |
| **Replay Attack** | Reusing old authentication | OTP is time-based (30-sec window) | speakeasy TOTP |

---

### 🔍 Attack Simulation Examples

**Scenario 1: Password Database Leak**
```
Attack: Attacker obtains database dump with hashed passwords
Defense: bcrypt + salt → Cannot reverse hashes, cannot use rainbow tables
Result: ✅ Passwords remain safe
```

**Scenario 2: Stolen JWT Token**
```
Attack: Attacker intercepts valid JWT token
Defense: Token expires in 1 hour, MFA required for new sessions
Result: ✅ Limited attack window
```

**Scenario 3: File Tampering**
```
Attack: Admin modifies encrypted file bytes directly
Defense: Digital signature verification fails
Console Output: "WARNING: Integrity Check Failed!"
Result: ✅ User warned of tampering
```

---

## 📊 Encoding Techniques Used

| Data Type | Encoding | Purpose |
|-----------|----------|---------|
| Digital Signatures | Base64 | Safe storage in database/JSON |
| Encrypted AES Keys | Base64 | Transport-safe binary data |
| File Hashes | Hexadecimal | Human-readable integrity check |
| IVs (Initialization Vectors) | Hexadecimal | Consistent length representation |
| QR Codes | Data URL (Base64 image) | Inline image display |
| TOTP Secrets | Base32 | Authenticator app compatibility |

### Encoding Demo

**Original Text**: `Hello World`
**Base64 Encoded**: `SGVsbG8gV29ybGQ=`
**SHA-256 Hash**: `a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e`

---

## 📚 References

- NIST SP 800-63B: Digital Identity Guidelines (Authentication)
- OWASP Top 10: Web Application Security Risks
- RFC 6238: TOTP Algorithm
- AES-256: FIPS 197 Standard
- RSA: PKCS #1 v2.2
