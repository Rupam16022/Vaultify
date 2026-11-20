# Vaultify | Zero-Knowledge Web Password Manager

> **Live Production Deployment**: [https://vaultify-95j9.onrender.com](https://vaultify-95j9.onrender.com)  
> **Interactive Cryptographic Test Suite**: [https://vaultify-95j9.onrender.com/crypto-test](https://vaultify-95j9.onrender.com/crypto-test)  
> **GitHub Repository**: [https://github.com/Rupam16022/Vaultify](https://github.com/Rupam16022/Vaultify)

---

## Overview

**Vaultify** is an enterprise-grade, zero-knowledge password manager designed on the principle that the host server is an untrusted storage provider. The server never receives, generates, stores, or handles the user's master password, derived encryption keys, or decrypted vault items.

All cryptographic operations are performed natively inside the browser using the **W3C Web Cryptography API** (`globalThis.crypto.subtle`) with **0 external npm crypto dependencies**.

---

## Key Cryptographic Features

1. **Zero-Knowledge Key Derivation**:
   - **PBKDF2-HMAC-SHA256 with 600,000 iterations** (OWASP Standard) + 16-byte cryptographically secure random per-user salt.
   - **HKDF-SHA256 Domain Separation**:
     - `vaultify-auth` &rarr; 256-bit **Auth Key** (hex string) sent to the server over HTTPS for authentication.
     - `vaultify-enc` &rarr; 256-bit **Encryption Key** (AES-256-GCM) with `extractable: false`, retained strictly in browser memory during an active session.
2. **Dumb-Server Vault Storage**:
   - The vault is encrypted with **AES-256-GCM** using a **fresh, random 12-byte IV** on every save.
   - The server stores only `{ ciphertext, iv, version, updated_at }`. The server cannot read or modify any stored record without failing the 128-bit authentication tag.
3. **No Persistent Client Storage**:
   - `localStorage` and `sessionStorage` are strictly forbidden for keys, tokens, and decrypted data.
   - State is managed in Redux Toolkit and purged on logout or lock.
4. **5-Minute Inactivity Auto-Lock**:
   - An inactivity monitor detects user idle time and purges all in-memory keys and decrypted records after 5 minutes.
5. **30-Second Secure Clipboard Wipe**:
   - Passwords copied to the clipboard initiate a 30-second security countdown, after which the clipboard is automatically overwritten with an empty string.
6. **Unbiased Password Generator**:
   - Cryptographic rejection sampling eliminates modulo bias, guaranteeing mathematically uniform character distributions.
7. **HaveIBeenPwned (HIBP) k-Anonymity Breach Check**:
   - Computes SHA-1 locally in memory. Only the first 5 hexadecimal characters are sent to the HIBP API; suffix matching occurs purely in the browser.
8. **Time-Based Two-Factor Authentication (TOTP 2FA)**:
   - Full TOTP support (Google Authenticator, Authy, 1Password).
   - TOTP secrets are encrypted at rest in PostgreSQL with AES-256-GCM using `TOTP_ENC_KEY`.
   - Step-up authentication uses scope-separated JWTs (`scope: "pre-auth"`).
9. **User Enumeration Defense**:
   - `/api/auth/salt` generates a deterministic HMAC-SHA256 pseudo-salt for unknown emails, preventing account enumeration timing attacks.

---

## Architectural Layout

```
Vaulty/
├── client/                     # Vite + React 19 + TypeScript + Redux Toolkit
│   ├── src/
│   │   ├── components/         # AuthScreen, VaultDashboard, AddEditModal,
│   │   │                       # RawDataModal, TwoFactorModal, PasswordGeneratorModal
│   │   ├── features/           # authSlice, vaultSlice
│   │   ├── hooks/              # useInactivityTimer (5m), useClipboard (30s wipe)
│   │   ├── lib/
│   │   │   ├── crypto.ts       # Heavily commented zero-knowledge cryptographic engine
│   │   │   ├── crypto.test.ts  # Vitest test suite (17 comprehensive tests)
│   │   │   ├── keyStore.ts     # Ephemeral in-memory CryptoKey store
│   │   │   └── api.ts          # Ephemeral token API client
│   │   ├── pages/              # CryptoTestPage (/crypto-test)
│   │   ├── App.tsx
│   │   └── main.tsx
├── server/                     # Node.js + Express + TypeScript
│   ├── src/
│   │   ├── db/                 # PostgreSQL pool & automated migrations
│   │   ├── middleware/         # Helmet (HSTS), HTTPS redirect, rateLimiter, JWT auth
│   │   ├── routes/             # authRoutes, vaultRoutes, twoFactorRoutes
│   │   ├── schemas/            # Zod validation schemas
│   │   ├── services/           # AES-256-GCM encryption of TOTP secrets at rest
│   │   ├── app.ts              # Express configuration & single-origin SPA serving
│   │   └── server.ts           # Server bootstrap
├── render.yaml                 # Render Infrastructure-as-Code deployment blueprint
├── THREAT_MODEL.md             # Formal security & STRIDE threat model documentation
└── README.md
```

---

## Environment Variables

| Variable | Description |
|:---|:---|
| `DATABASE_URL` | PostgreSQL connection string (Neon with SSL enabled) |
| `JWT_SECRET` | Secret key used to sign session JWTs (24h validity) |
| `TOTP_ENC_KEY` | 32-byte hexadecimal key for encrypting TOTP secrets at rest |
| `SALT_PEPPER` | Secret string for computing deterministic pseudo-salts |
| `NODE_ENV` | `production` or `development` |
| `PORT` | Listening port (Default: `10000` on Render, `5000` locally) |

---

## Verification & Testing Guide

### 1. Interactive In-Browser Crypto Verification
Visit the live test suite: **[https://vaultify-95j9.onrender.com/crypto-test](https://vaultify-95j9.onrender.com/crypto-test)**
- **Test Key Derivation**: Live PBKDF2 (600,000 iterations) + HKDF domain separation.
- **Test Authenticated Round Trip**: Encrypt and decrypt arbitrary JSON using AES-256-GCM.
- **Test Wrong Key Rejection**: Observe native Web Crypto `OperationError` rejection.
- **Test Tampered Ciphertext**: Flipped bits trigger authentication tag validation failure.
- **Test Rejection Sampling**: Verify unbiased password generation.

### 2. View Raw Data Inspector
1. Log in to your vault at [https://vaultify-95j9.onrender.com](https://vaultify-95j9.onrender.com).
2. Click **View Raw Data** in the header.
3. Review the exact JSON payload retrieved from Neon PostgreSQL: only ciphertext and IV are present.

### 3. Automated Test Suite
Run the 17 unit tests locally:
```bash
npm run test:run
```
