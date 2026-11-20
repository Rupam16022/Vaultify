import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { AppDispatch } from '../store';
import { loginSuccess } from '../features/auth/authSlice';
import { fetchVault } from '../features/vault/vaultSlice';
import { api } from '../lib/api';
import { keyStore } from '../lib/keyStore';
import { generateSalt, deriveKeys } from '../lib/crypto';
import { Shield, Lock, Key, AlertCircle, RefreshCw, CheckCircle2, Eye, EyeOff } from 'lucide-react';

export const AuthScreen: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const [mode, setMode] = useState<'login' | 'register'>('login');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Status & Progress
  const [isLoading, setIsLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // 2FA state
  const [require2fa, setRequire2fa] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null);

  const calculatePasswordStrength = (pwd: string) => {
    let score = 0;
    if (pwd.length >= 12) score += 1;
    if (pwd.length >= 16) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1;
    return score;
  };

  const strength = calculatePasswordStrength(password);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (password !== confirmPassword) {
      setErrorMessage('Master passwords do not match.');
      return;
    }
    if (password.length < 12) {
      setErrorMessage('Master password must be at least 12 characters.');
      return;
    }

    try {
      setIsLoading(true);
      setStatusMessage('Generating 16-byte cryptographic salt...');
      const salt = generateSalt();

      setStatusMessage('Deriving 256-bit keys with 600,000 PBKDF2 iterations...');
      const { authKeyHex, encryptionKey } = await deriveKeys(password, salt);

      setStatusMessage('Registering account with Auth Key over HTTPS...');
      const res = await api.register(email, salt, authKeyHex);

      if (res.token && res.user) {
        // Keep non-extractable Encryption Key strictly in memory
        keyStore.setKey(encryptionKey);
        dispatch(loginSuccess({ token: res.token, user: res.user }));
        dispatch(fetchVault());
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    try {
      setIsLoading(true);
      setStatusMessage('Retrieving salt for authentication...');
      const saltRes = await api.getSalt(email);

      setStatusMessage('Deriving keys with 600,000 PBKDF2 iterations in browser...');
      const { authKeyHex, encryptionKey } = await deriveKeys(password, saltRes.salt);

      setStatusMessage('Verifying credentials with server...');
      const loginRes = await api.login(email, authKeyHex);

      if (loginRes.require2fa && loginRes.preAuthToken) {
        setRequire2fa(true);
        setPreAuthToken(loginRes.preAuthToken);
        // Temporarily store key in memory pending 2FA
        keyStore.setKey(encryptionKey);
        setStatusMessage(null);
        return;
      }

      if (loginRes.token && loginRes.user) {
        // Store non-extractable Encryption Key strictly in memory
        keyStore.setKey(encryptionKey);
        dispatch(loginSuccess({ token: loginRes.token, user: loginRes.user }));
        dispatch(fetchVault());
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Login failed. Check your email or password.');
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  const handleVerify2fa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!preAuthToken) return;

    try {
      setIsLoading(true);
      setStatusMessage('Verifying 2FA authentication...');

      const response = await fetch('/api/auth/2fa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${preAuthToken}`,
        },
        body: JSON.stringify({ code: totpCode.trim(), token: totpCode.trim() }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Invalid 2FA code.');
      }

      dispatch(loginSuccess({ token: data.token, user: data.user }));
      dispatch(fetchVault());
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Two-factor verification failed');
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#090d16', padding: '1.5rem', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <div style={{ width: '100%', maxWidth: '440px', background: '#111827', border: '1px solid #1f2937', borderRadius: '16px', padding: '2rem', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)', color: '#f9fafb' }}>
        
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ display: 'inline-flex', background: 'linear-gradient(135deg, #2563eb, #3b82f6)', padding: '0.75rem', borderRadius: '12px', boxShadow: '0 10px 15px -3px rgba(37, 99, 235, 0.4)', marginBottom: '1rem' }}>
            <Lock size={28} color="#fff" />
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, margin: '0 0 0.25rem', letterSpacing: '-0.02em', color: '#fff' }}>
            Vaultify
          </h1>
          <p style={{ margin: 0, fontSize: '0.875rem', color: '#9ca3af' }}>
            Zero-Knowledge Cryptographic Vault
          </p>
        </div>

        {/* Mode Toggle */}
        {!require2fa && (
          <div style={{ display: 'flex', background: '#1f2937', padding: '0.25rem', borderRadius: '8px', marginBottom: '1.5rem' }}>
            <button
              onClick={() => { setMode('login'); setErrorMessage(null); }}
              style={{ flex: 1, padding: '0.5rem', border: 'none', background: mode === 'login' ? '#2563eb' : 'transparent', color: mode === 'login' ? '#fff' : '#9ca3af', fontWeight: 600, fontSize: '0.875rem', borderRadius: '6px', cursor: 'pointer', transition: 'all 0.2s' }}
            >
              Sign In
            </button>
            <button
              onClick={() => { setMode('register'); setErrorMessage(null); }}
              style={{ flex: 1, padding: '0.5rem', border: 'none', background: mode === 'register' ? '#2563eb' : 'transparent', color: mode === 'register' ? '#fff' : '#9ca3af', fontWeight: 600, fontSize: '0.875rem', borderRadius: '6px', cursor: 'pointer', transition: 'all 0.2s' }}
            >
              Create Vault
            </button>
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', padding: '0.75rem', marginBottom: '1.25rem', display: 'flex', gap: '0.5rem', alignItems: 'center', color: '#fca5a5', fontSize: '0.85rem' }}>
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* 2FA Step */}
        {require2fa ? (
          <form onSubmit={handleVerify2fa}>
            <div style={{ marginBottom: '1.25rem', textAlign: 'center' }}>
              <p style={{ fontSize: '0.875rem', color: '#9ca3af', margin: '0 0 1rem' }}>
                Enter the 6-digit code from your authenticator app, or an 8-character backup recovery code.
              </p>
              <input
                type="text"
                required
                maxLength={12}
                placeholder="123456 or Backup Code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.toUpperCase())}
                style={{ width: '100%', padding: '0.75rem', textAlign: 'center', fontSize: '1.25rem', letterSpacing: '0.2em', background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff', boxSizing: 'border-box' }}
              />
            </div>

            <button
              type="submit"
              disabled={isLoading || totpCode.trim().length < 6}
              style={{ width: '100%', padding: '0.75rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '8px', fontWeight: 700, fontSize: '0.95rem', cursor: isLoading ? 'not-allowed' : 'pointer' }}
            >
              {isLoading ? 'Verifying...' : 'Authenticate & Unlock'}
            </button>
          </form>
        ) : (
          <form onSubmit={mode === 'login' ? handleLogin : handleRegister}>
            {/* Email */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem' }}>
                Email Address
              </label>
              <input
                type="email"
                required
                placeholder="you@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{ width: '100%', padding: '0.7rem 0.85rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff', fontSize: '0.9rem', boxSizing: 'border-box' }}
              />
            </div>

            {/* Master Password */}
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db' }}>
                  Master Password
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />} {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="••••••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ width: '100%', padding: '0.7rem 0.85rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff', fontSize: '0.9rem', boxSizing: 'border-box' }}
              />

              {/* Strength Meter (Register mode) */}
              {mode === 'register' && password && (
                <div style={{ marginTop: '0.5rem' }}>
                  <div style={{ display: 'flex', gap: '4px', height: '4px' }}>
                    {[1, 2, 3, 4, 5].map((lvl) => (
                      <div
                        key={lvl}
                        style={{
                          flex: 1,
                          borderRadius: '2px',
                          background:
                            lvl <= strength
                              ? strength <= 2
                                ? '#ef4444'
                                : strength <= 3
                                ? '#f59e0b'
                                : '#10b981'
                              : '#374151',
                        }}
                      />
                    ))}
                  </div>
                  <span style={{ fontSize: '0.7rem', color: strength < 3 ? '#f87171' : strength < 4 ? '#fbbf24' : '#34d399', marginTop: '0.25rem', display: 'block' }}>
                    {strength <= 2 ? 'Weak' : strength <= 3 ? 'Medium' : strength <= 4 ? 'Strong' : 'Very Strong (OWASP Recommended)'}
                  </span>
                </div>
              )}
            </div>

            {/* Confirm Password (Register mode) */}
            {mode === 'register' && (
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem' }}>
                  Confirm Master Password
                </label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  style={{ width: '100%', padding: '0.7rem 0.85rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff', fontSize: '0.9rem', boxSizing: 'border-box' }}
                />
              </div>
            )}

            {/* Zero Knowledge Warning */}
            <div style={{ background: 'rgba(59, 130, 246, 0.08)', border: '1px solid #1e3a8a', borderRadius: '8px', padding: '0.75rem', marginBottom: '1.5rem', display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
              <Shield size={16} color="#60a5fa" style={{ flexShrink: 0, marginTop: '2px' }} />
              <p style={{ margin: 0, fontSize: '0.75rem', color: '#93c5fd', lineHeight: 1.4 }}>
                <strong>Zero-Knowledge Principle:</strong> Your master password never leaves your device. It is used locally to derive your encryption keys. If you lose your password, your vault data is mathematically irrecoverable.
              </p>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '0.8rem',
                background: '#2563eb',
                color: '#fff',
                border: 'none',
                borderRadius: '8px',
                fontWeight: 700,
                fontSize: '0.95rem',
                cursor: isLoading ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                boxShadow: '0 4px 6px -1px rgba(37, 99, 235, 0.3)',
              }}
            >
              {isLoading ? <RefreshCw className="animate-spin" size={18} /> : <Key size={18} />}
              {isLoading ? 'Deriving Keys...' : mode === 'login' ? 'Unlock Vault' : 'Create Encrypted Vault'}
            </button>
          </form>
        )}

        {/* Live Derivation Status Bar */}
        {statusMessage && (
          <div style={{ marginTop: '1rem', textAlign: 'center', color: '#60a5fa', fontSize: '0.8rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem' }}>
            <RefreshCw size={14} className="animate-spin" />
            <span>{statusMessage}</span>
          </div>
        )}
      </div>
    </div>
  );
};
