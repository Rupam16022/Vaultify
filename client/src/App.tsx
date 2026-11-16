import React, { useState, useEffect } from 'react';
import { CryptoTestPage } from './pages/CryptoTestPage';
import { Shield, Lock, ExternalLink, CheckCircle } from 'lucide-react';

export const App: React.FC = () => {
  const [currentPath, setCurrentPath] = useState(window.location.pathname);

  useEffect(() => {
    const handlePopState = () => setCurrentPath(window.location.pathname);
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigate = (path: string) => {
    window.history.pushState({}, '', path);
    setCurrentPath(path);
  };

  if (currentPath === '/crypto-test') {
    return (
      <div>
        <nav style={{ background: '#0f172a', padding: '0.75rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ color: '#fff', fontWeight: 700, fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={20} color="#38bdf8" /> Vaultify
          </span>
          <button
            onClick={() => navigate('/')}
            style={{ background: 'transparent', border: '1px solid #334155', color: '#94a3b8', padding: '0.4rem 0.8rem', borderRadius: '4px', cursor: 'pointer' }}
          >
            ← Back to Home
          </button>
        </nav>
        <CryptoTestPage />
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', color: '#f8fafc', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <header style={{ borderBottom: '1px solid #1e293b', padding: '1.25rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ background: '#2563eb', padding: '0.5rem', borderRadius: '8px', display: 'flex' }}>
            <Lock size={22} color="#fff" />
          </div>
          <div>
            <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#fff' }}>Vaultify</span>
            <span style={{ marginLeft: '0.5rem', fontSize: '0.75rem', background: '#1e3a8a', color: '#93c5fd', padding: '0.2rem 0.5rem', borderRadius: '999px', fontWeight: 600 }}>Zero-Knowledge</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <a
            href="/api/health"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#94a3b8', textDecoration: 'none', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            Health Check <ExternalLink size={14} />
          </a>
          <button
            onClick={() => navigate('/crypto-test')}
            style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '0.5rem 1rem', borderRadius: '6px', fontWeight: 600, cursor: 'pointer', fontSize: '0.85rem' }}
          >
            Open Crypto Test Suite →
          </button>
        </div>
      </header>

      <main style={{ maxWidth: '900px', margin: '4rem auto', padding: '0 1.5rem', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', background: '#1e293b', padding: '0.4rem 1rem', borderRadius: '999px', fontSize: '0.85rem', color: '#38bdf8', marginBottom: '1.5rem' }}>
          <CheckCircle size={16} /> Phase 1 Live Deployment Active
        </div>

        <h1 style={{ fontSize: '3rem', fontWeight: 800, lineHeight: 1.15, letterSpacing: '-0.03em', margin: '0 0 1.5rem' }}>
          Zero-Knowledge Password Management. <br />
          <span style={{ background: 'linear-gradient(to right, #38bdf8, #818cf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Mathematically Verifiable.
          </span>
        </h1>

        <p style={{ fontSize: '1.15rem', color: '#94a3b8', maxWidth: '650px', margin: '0 auto 2.5rem', lineHeight: 1.6 }}>
          Your master password never touches the server. All cryptographic operations happen exclusively in your browser via the native Web Crypto API.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem' }}>
          <button
            onClick={() => navigate('/crypto-test')}
            style={{ background: '#2563eb', color: '#fff', padding: '0.85rem 1.75rem', borderRadius: '8px', border: 'none', fontWeight: 700, fontSize: '1rem', cursor: 'pointer', boxShadow: '0 10px 15px -3px rgba(37, 99, 235, 0.3)' }}
          >
            Run In-Browser Crypto Verification
          </button>
          <a
            href="https://github.com/Rupam16022/Vaultify"
            target="_blank"
            rel="noopener noreferrer"
            style={{ background: '#1e293b', color: '#f8fafc', padding: '0.85rem 1.75rem', borderRadius: '8px', textDecoration: 'none', fontWeight: 600, fontSize: '1rem', border: '1px solid #334155', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            GitHub Repository <ExternalLink size={16} />
          </a>
        </div>

        <div style={{ marginTop: '4rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.5rem', textAlign: 'left' }}>
          <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '10px', padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: '0 0 0.5rem', color: '#38bdf8' }}>600,000 PBKDF2 Iterations</h3>
            <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: 0, lineHeight: 1.5 }}>
              OWASP-grade key stretching with per-user 16-byte random salt prevents offline dictionary attacks.
            </p>
          </div>
          <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '10px', padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: '0 0 0.5rem', color: '#38bdf8' }}>Domain Separation (HKDF)</h3>
            <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: 0, lineHeight: 1.5 }}>
              Extracts distinct Auth Key and non-extractable AES-256-GCM Encryption Key. Compromising one reveals nothing about the other.
            </p>
          </div>
          <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '10px', padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: '0 0 0.5rem', color: '#38bdf8' }}>Untrusted Server Model</h3>
            <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: 0, lineHeight: 1.5 }}>
              The server stores only encrypted blobs and 12-byte IVs. Plaintext data and keys never exist in server memory or disk.
            </p>
          </div>
        </div>
      </main>
    </div>
  );
};
