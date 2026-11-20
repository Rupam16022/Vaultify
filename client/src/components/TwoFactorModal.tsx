import React, { useState, useEffect } from 'react';
import { getApiToken } from '../lib/api';
import { X, ShieldCheck, Smartphone, RefreshCw, AlertCircle, CheckCircle2 } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export const TwoFactorModal: React.FC<Props> = ({ isOpen, onClose }) => {
  const [isEnabled, setIsEnabled] = useState(false);
  const [loading, setLoading] = useState(false);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/auth/2fa/status', {
        headers: { Authorization: `Bearer ${getApiToken()}` },
      });
      const data = await res.json();
      if (res.ok) {
        setIsEnabled(Boolean(data.enabled));
      }
    } catch {
      // Ignored
    } finally {
      setLoading(false);
    }
  };

  const handleStartSetup = async () => {
    try {
      setLoading(true);
      setErrorMessage(null);
      const res = await fetch('/api/auth/2fa/setup', {
        method: 'POST',
        headers: { Authorization: `Bearer ${getApiToken()}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to start setup');
      setQrCode(data.qrCode);
      setSecret(data.secret);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setErrorMessage(null);
      const res = await fetch('/api/auth/2fa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${getApiToken()}`,
        },
        body: JSON.stringify({ code: verifyCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Invalid code');
      setIsEnabled(true);
      setQrCode(null);
      setSecret(null);
      setVerifyCode('');
      setSuccessMessage('Two-Factor Authentication is now active on your account!');
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setErrorMessage(null);
      const res = await fetch('/api/auth/2fa/disable', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${getApiToken()}`,
        },
        body: JSON.stringify({ code: disableCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to disable');
      setIsEnabled(false);
      setDisableCode('');
      setSuccessMessage('Two-Factor Authentication has been disabled.');
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : 'Disable failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      setErrorMessage(null);
      setSuccessMessage(null);
      fetchStatus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
      <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '14px', width: '100%', maxWidth: '480px', padding: '1.75rem', color: '#f9fafb', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6)' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Smartphone size={22} color="#38bdf8" />
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0 }}>Two-Factor Authentication (TOTP)</h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {errorMessage && (
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', padding: '0.75rem', marginBottom: '1rem', color: '#fca5a5', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={16} /> {errorMessage}
          </div>
        )}

        {successMessage && (
          <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #10b981', borderRadius: '8px', padding: '0.75rem', marginBottom: '1rem', color: '#6ee7b7', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <CheckCircle2 size={16} /> {successMessage}
          </div>
        )}

        {/* Status display */}
        <div style={{ background: '#090d16', border: '1px solid #1f2937', borderRadius: '8px', padding: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85rem', color: '#9ca3af' }}>Current 2FA Status:</span>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: isEnabled ? '#34d399' : '#f87171', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <ShieldCheck size={16} /> {isEnabled ? 'Active & Protected' : 'Disabled'}
            </span>
          </div>
          <p style={{ margin: '0.5rem 0 0', fontSize: '0.75rem', color: '#6b7280' }}>
            TOTP secret is stored encrypted at rest using AES-256-GCM.
          </p>
        </div>

        {/* If Not Enabled: Setup Flow */}
        {!isEnabled && !qrCode && (
          <div>
            <p style={{ fontSize: '0.85rem', color: '#d1d5db', lineHeight: 1.5, marginBottom: '1.25rem' }}>
              Protect your vault with Time-Based One-Time Passwords (TOTP) compatible with Google Authenticator, Authy, or 1Password.
            </p>
            <button
              onClick={handleStartSetup}
              disabled={loading}
              style={{ width: '100%', padding: '0.75rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '8px', fontWeight: 700, fontSize: '0.9rem', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
            >
              {loading ? <RefreshCw className="animate-spin" size={16} /> : <Smartphone size={16} />}
              Configure Authenticator App
            </button>
          </div>
        )}

        {/* QR Code Presentation */}
        {!isEnabled && qrCode && (
          <form onSubmit={handleConfirmVerify}>
            <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
              <p style={{ fontSize: '0.85rem', color: '#d1d5db', margin: '0 0 0.75rem' }}>
                Scan this QR code with your authenticator app:
              </p>
              <img
                src={qrCode}
                alt="2FA QR Code"
                style={{ width: '180px', height: '180px', borderRadius: '8px', background: '#fff', padding: '8px' }}
              />
              <div style={{ marginTop: '0.75rem' }}>
                <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Manual Entry Key:</span>
                <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#38bdf8', letterSpacing: '0.05em', marginTop: '0.2rem' }}>
                  {secret}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem', textAlign: 'center' }}>
                Enter the 6-Digit Code to Confirm
              </label>
              <input
                type="text"
                required
                maxLength={6}
                placeholder="123456"
                value={verifyCode}
                onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ''))}
                style={{ width: '100%', padding: '0.7rem', textAlign: 'center', fontSize: '1.4rem', letterSpacing: '0.4em', background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff', boxSizing: 'border-box' }}
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setQrCode(null)}
                style={{ flex: 1, padding: '0.65rem', background: '#1f2937', color: '#9ca3af', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading || verifyCode.length !== 6}
                style={{ flex: 2, padding: '0.65rem', background: '#10b981', color: '#fff', border: 'none', borderRadius: '6px', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: '0.85rem' }}
              >
                {loading ? 'Activating...' : 'Verify & Enable 2FA'}
              </button>
            </div>
          </form>
        )}

        {/* If Enabled: Option to Disable */}
        {isEnabled && (
          <form onSubmit={handleDisable}>
            <p style={{ fontSize: '0.85rem', color: '#d1d5db', lineHeight: 1.5, marginBottom: '1rem' }}>
              To turn off two-factor authentication, enter the current 6-digit code from your authenticator:
            </p>
            <div style={{ marginBottom: '1rem' }}>
              <input
                type="text"
                required
                maxLength={6}
                placeholder="000000"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ''))}
                style={{ width: '100%', padding: '0.65rem', textAlign: 'center', fontSize: '1.25rem', letterSpacing: '0.3em', background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff', boxSizing: 'border-box' }}
              />
            </div>
            <button
              type="submit"
              disabled={loading || disableCode.length !== 6}
              style={{ width: '100%', padding: '0.65rem', background: '#ef4444', color: '#fff', border: 'none', borderRadius: '8px', fontWeight: 700, fontSize: '0.85rem', cursor: loading ? 'not-allowed' : 'pointer' }}
            >
              {loading ? 'Disabling...' : 'Disable 2FA'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
