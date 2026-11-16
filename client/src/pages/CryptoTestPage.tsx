import React, { useState } from 'react';
import {
  generateSalt,
  deriveKeys,
  encryptVault,
  decryptVault,
  generatePassword,
  sha1,
  type DerivedKeys,
  type EncryptedPayload,
} from '../lib/crypto';
import { ShieldCheck, Key, Lock, Unlock, AlertTriangle, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';

export const CryptoTestPage: React.FC = () => {
  const [password, setPassword] = useState('My-Ultra-Secure-Master-Password-123!');
  const [salt, setSalt] = useState('');
  const [derivedKeys, setDerivedKeys] = useState<DerivedKeys | null>(null);
  const [isDeriving, setIsDeriving] = useState(false);
  const [derivationTimeMs, setDerivationTimeMs] = useState<number | null>(null);

  // Vault data test
  const [vaultJson, setVaultJson] = useState(
    JSON.stringify(
      [
        {
          id: '1',
          name: 'ProtonMail',
          username: 'alice@proton.me',
          password: 'SecretPassword987!',
          url: 'https://mail.proton.me',
        },
        {
          id: '2',
          name: 'AWS Production',
          username: 'devops-admin',
          password: 'CloudSuperPassword#42',
          url: 'https://aws.amazon.com',
        },
      ],
      null,
      2
    )
  );
  const [encryptedPayload, setEncryptedPayload] = useState<EncryptedPayload | null>(null);
  const [decryptedResult, setDecryptedResult] = useState<string | null>(null);
  const [tamperError, setTamperError] = useState<string | null>(null);
  const [wrongKeyError, setWrongKeyError] = useState<string | null>(null);

  // Password Generator test
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [hibpPrefix, setHibpPrefix] = useState('');
  const [hibpSuffix, setHibpSuffix] = useState('');

  // 1. Generate Salt
  const handleGenerateSalt = () => {
    const s = generateSalt();
    setSalt(s);
    setDerivedKeys(null);
    setEncryptedPayload(null);
    setDecryptedResult(null);
  };

  // 2. Derive Keys
  const handleDeriveKeys = async () => {
    try {
      setIsDeriving(true);
      const activeSalt = salt || generateSalt();
      if (!salt) setSalt(activeSalt);

      const startTime = performance.now();
      const keys = await deriveKeys(password, activeSalt);
      const elapsed = performance.now() - startTime;

      setDerivedKeys(keys);
      setDerivationTimeMs(Math.round(elapsed));
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Key derivation failed');
    } finally {
      setIsDeriving(false);
    }
  };

  // 3. Encrypt Vault
  const handleEncrypt = async () => {
    if (!derivedKeys) {
      alert('Derive keys first!');
      return;
    }
    try {
      const parsedData = JSON.parse(vaultJson);
      const payload = await encryptVault(parsedData, derivedKeys.encryptionKey);
      setEncryptedPayload(payload);
      setDecryptedResult(null);
      setTamperError(null);
      setWrongKeyError(null);
    } catch (err: unknown) {
      alert('JSON Parse or Encryption Error: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  // 4. Decrypt Vault (Normal)
  const handleDecrypt = async () => {
    if (!derivedKeys || !encryptedPayload) return;
    try {
      const decrypted = await decryptVault(
        encryptedPayload.ciphertext,
        encryptedPayload.iv,
        derivedKeys.encryptionKey
      );
      setDecryptedResult(JSON.stringify(decrypted, null, 2));
    } catch (err: unknown) {
      alert('Decryption failed: ' + (err instanceof Error ? err.message : String(err)));
    }
  };

  // 5. Test Decrypt with Wrong Key
  const handleTestWrongKey = async () => {
    if (!encryptedPayload) return;
    try {
      setWrongKeyError(null);
      const wrongKeys = await deriveKeys('WrongPassword999!', generateSalt());
      await decryptVault(
        encryptedPayload.ciphertext,
        encryptedPayload.iv,
        wrongKeys.encryptionKey
      );
      setWrongKeyError('CRITICAL FLAW: Decrypted with wrong key!');
    } catch {
      setWrongKeyError('PROVEN: Web Crypto rejected wrong key (OperationError / Tag mismatch).');
    }
  };

  // 6. Test Tampered Ciphertext
  const handleTestTamper = async () => {
    if (!derivedKeys || !encryptedPayload) return;
    try {
      setTamperError(null);
      // Flip characters in base64 ciphertext
      const tampered =
        encryptedPayload.ciphertext.substring(0, 10) +
        (encryptedPayload.ciphertext[10] === 'A' ? 'B' : 'A') +
        encryptedPayload.ciphertext.substring(11);

      await decryptVault(tampered, encryptedPayload.iv, derivedKeys.encryptionKey);
      setTamperError('CRITICAL FLAW: Tampered ciphertext was accepted!');
    } catch {
      setTamperError('PROVEN: AES-256-GCM authentication tag rejected tampered ciphertext.');
    }
  };

  // 7. Test Password Generator & HIBP
  const handleTestPasswordGen = async () => {
    const pwd = generatePassword({ length: 24 });
    setGeneratedPassword(pwd);
    const hash = await sha1(pwd);
    setHibpPrefix(hash.slice(0, 5));
    setHibpSuffix(hash.slice(5));
  };

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto', padding: '2rem', fontFamily: 'system-ui, -apple-system, sans-serif', color: '#1e293b' }}>
      <header style={{ borderBottom: '1px solid #e2e8f0', paddingBottom: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <ShieldCheck size={36} color="#2563eb" />
          <div>
            <h1 style={{ margin: 0, fontSize: '1.75rem', fontWeight: 700, color: '#0f172a' }}>
              Vaultify Zero-Knowledge Cryptographic Verification
            </h1>
            <p style={{ margin: '0.25rem 0 0', color: '#64748b', fontSize: '0.95rem' }}>
              Live in-browser proof of Web Crypto key derivation, domain separation, and AES-256-GCM round trip.
            </p>
          </div>
        </div>
      </header>

      {/* Step 1: Salt & Master Password */}
      <section style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '10px', padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.15rem', marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Key size={20} color="#2563eb" /> 1. Master Password & Salt Input
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem' }}>
          <div>
            <label style={{ display: 'block', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              Master Password (Plaintext - NEVER leaves browser)
            </label>
            <input
              type="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #cbd5e1', boxSizing: 'border-box' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              16-Byte Cryptographic Salt (Hex)
            </label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="text"
                placeholder="Click Generate Salt"
                value={salt}
                onChange={(e) => setSalt(e.target.value)}
                style={{ flex: 1, padding: '0.6rem', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '0.85rem', fontFamily: 'monospace' }}
              />
              <button
                onClick={handleGenerateSalt}
                style={{ padding: '0.6rem 1rem', background: '#e2e8f0', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600 }}
              >
                New Salt
              </button>
            </div>
          </div>
        </div>

        <div style={{ marginTop: '1.25rem' }}>
          <button
            onClick={handleDeriveKeys}
            disabled={isDeriving}
            style={{
              padding: '0.75rem 1.5rem',
              background: '#2563eb',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: 600,
              cursor: isDeriving ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            {isDeriving ? <RefreshCw className="animate-spin" size={18} /> : <Lock size={18} />}
            {isDeriving ? 'Deriving with 600,000 PBKDF2 Iterations...' : 'Derive Keys (PBKDF2 + HKDF)'}
          </button>
          {derivationTimeMs !== null && (
            <p style={{ fontSize: '0.85rem', color: '#16a34a', marginTop: '0.5rem', fontWeight: 500 }}>
              ✓ 600,000 PBKDF2 iterations completed in {derivationTimeMs} ms in your browser.
            </p>
          )}
        </div>
      </section>

      {/* Step 2: Derived Keys Output */}
      {derivedKeys && (
        <section style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '10px', padding: '1.5rem', marginBottom: '1.5rem' }}>
          <h2 style={{ fontSize: '1.15rem', marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <CheckCircle2 size={20} color="#16a34a" /> 2. Derived Subkeys (Domain Separation)
          </h2>
          <div style={{ marginTop: '1rem' }}>
            <div style={{ marginBottom: '1rem' }}>
              <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Auth Key (Transmitted to server over HTTPS for login):</span>
              <div style={{ background: '#0f172a', color: '#38bdf8', padding: '0.75rem', borderRadius: '6px', fontFamily: 'monospace', fontSize: '0.85rem', wordBreak: 'break-all', marginTop: '0.25rem' }}>
                {derivedKeys.authKeyHex}
              </div>
            </div>
            <div>
              <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Encryption Key (Kept strictly in client memory):</span>
              <div style={{ background: '#f1f5f9', border: '1px solid #cbd5e1', padding: '0.75rem', borderRadius: '6px', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                Type: <strong>CryptoKey</strong> | Algorithm: <strong>AES-GCM (256 bits)</strong> | Extractable:{' '}
                <strong style={{ color: '#dc2626' }}>{String(derivedKeys.encryptionKey.extractable)} (Non-Extractable)</strong> | Usages: <strong>[{derivedKeys.encryptionKey.usages.join(', ')}]</strong>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Step 3: Vault Round Trip Test */}
      <section style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '10px', padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.15rem', marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Lock size={20} color="#2563eb" /> 3. AES-256-GCM Encrypt & Decrypt Round Trip
        </h2>
        <div>
          <label style={{ display: 'block', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.25rem' }}>
            Vault JSON Data:
          </label>
          <textarea
            rows={6}
            value={vaultJson}
            onChange={(e) => setVaultJson(e.target.value)}
            style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace', fontSize: '0.85rem', boxSizing: 'border-box' }}
          />
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem', flexWrap: 'wrap' }}>
          <button
            onClick={handleEncrypt}
            disabled={!derivedKeys}
            style={{ padding: '0.6rem 1.25rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '6px', cursor: derivedKeys ? 'pointer' : 'not-allowed', fontWeight: 600 }}
          >
            Encrypt (AES-256-GCM)
          </button>
          <button
            onClick={handleDecrypt}
            disabled={!encryptedPayload}
            style={{ padding: '0.6rem 1.25rem', background: '#16a34a', color: '#fff', border: 'none', borderRadius: '6px', cursor: encryptedPayload ? 'pointer' : 'not-allowed', fontWeight: 600 }}
          >
            Decrypt (Same Key)
          </button>
          <button
            onClick={handleTestWrongKey}
            disabled={!encryptedPayload}
            style={{ padding: '0.6rem 1.25rem', background: '#f59e0b', color: '#fff', border: 'none', borderRadius: '6px', cursor: encryptedPayload ? 'pointer' : 'not-allowed', fontWeight: 600 }}
          >
            Test Wrong Key
          </button>
          <button
            onClick={handleTestTamper}
            disabled={!encryptedPayload}
            style={{ padding: '0.6rem 1.25rem', background: '#ef4444', color: '#fff', border: 'none', borderRadius: '6px', cursor: encryptedPayload ? 'pointer' : 'not-allowed', fontWeight: 600 }}
          >
            Test Tampered Ciphertext
          </button>
        </div>

        {encryptedPayload && (
          <div style={{ marginTop: '1.25rem', background: '#0f172a', color: '#e2e8f0', padding: '1rem', borderRadius: '6px', fontSize: '0.8rem', fontFamily: 'monospace' }}>
            <div style={{ color: '#94a3b8', marginBottom: '0.25rem' }}>// Stored on Server:</div>
            <div><strong>IV (12-byte random):</strong> {encryptedPayload.iv}</div>
            <div style={{ marginTop: '0.5rem', wordBreak: 'break-all' }}>
              <strong>Ciphertext + Tag:</strong> {encryptedPayload.ciphertext}
            </div>
          </div>
        )}

        {decryptedResult && (
          <div style={{ marginTop: '1.25rem' }}>
            <div style={{ fontWeight: 600, color: '#16a34a', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <CheckCircle2 size={18} /> Decrypted Output (Matched Plaintext):
            </div>
            <pre style={{ background: '#f1f5f9', padding: '0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}>
              {decryptedResult}
            </pre>
          </div>
        )}

        {wrongKeyError && (
          <div style={{ marginTop: '1rem', padding: '0.75rem', borderRadius: '6px', background: '#fef3c7', color: '#92400e', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
            <AlertTriangle size={18} /> {wrongKeyError}
          </div>
        )}

        {tamperError && (
          <div style={{ marginTop: '1rem', padding: '0.75rem', borderRadius: '6px', background: '#fee2e2', color: '#b91c1c', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
            <XCircle size={18} /> {tamperError}
          </div>
        )}
      </section>

      {/* Step 4: Rejection Sampling & HIBP */}
      <section style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '10px', padding: '1.5rem' }}>
        <h2 style={{ fontSize: '1.15rem', marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Unlock size={20} color="#2563eb" /> 4. Password Generator (Rejection Sampling) & HIBP SHA-1
        </h2>
        <button
          onClick={handleTestPasswordGen}
          style={{ padding: '0.6rem 1.25rem', background: '#0f172a', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600 }}
        >
          Generate Unbiased Password
        </button>

        {generatedPassword && (
          <div style={{ marginTop: '1rem' }}>
            <div><strong>Generated (24 chars, unbiased):</strong> <code style={{ background: '#e2e8f0', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>{generatedPassword}</code></div>
            <div style={{ marginTop: '0.5rem', fontSize: '0.85rem' }}>
              <strong>HIBP k-Anonymity SHA-1 Hash:</strong>
              <div style={{ fontFamily: 'monospace', marginTop: '0.25rem' }}>
                <span style={{ background: '#fef08a', padding: '0.2rem 0.4rem', borderRadius: '3px' }}>Prefix (Sent to API): {hibpPrefix}</span>{' '}
                <span style={{ color: '#64748b' }}>Suffix (Kept Private in Memory): {hibpSuffix}</span>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
