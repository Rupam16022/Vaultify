import React from 'react';
import { useSelector } from 'react-redux';
import { RootState } from '../store';
import { X, ShieldAlert, Database, Lock, Copy, Check } from 'lucide-react';
import { useClipboard } from '../hooks/useClipboard';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export const RawDataModal: React.FC<Props> = ({ isOpen, onClose }) => {
  const { rawCiphertext, rawIv, version, updatedAt, items } = useSelector((state: RootState) => state.vault);
  const { copyToClipboard, copiedId } = useClipboard();

  if (!isOpen) return null;

  const rawJson = JSON.stringify(
    {
      ciphertext: rawCiphertext,
      iv: rawIv,
      version,
      updated_at: updatedAt,
      total_encrypted_records: items.length,
    },
    null,
    2
  );

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
      <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '14px', width: '100%', maxWidth: '640px', padding: '1.75rem', color: '#f9fafb', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6)', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Database size={22} color="#38bdf8" />
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0 }}>Server-Stored Raw Data</h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Audit explanation */}
        <div style={{ background: 'rgba(59, 130, 246, 0.08)', border: '1px solid #1e3a8a', borderRadius: '8px', padding: '0.85rem', marginBottom: '1.25rem', fontSize: '0.8rem', color: '#93c5fd', lineHeight: 1.5 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 700, marginBottom: '0.25rem', color: '#60a5fa' }}>
            <Lock size={16} /> Zero-Knowledge Cryptographic Proof
          </div>
          This is the exact JSON payload stored in PostgreSQL on Neon. Notice that only <strong>AES-256-GCM ciphertext</strong> and a random <strong>12-byte IV</strong> exist on the server. The server host, database administrators, or an attacker with full database access cannot read your usernames, passwords, or URLs.
        </div>

        {/* Code block */}
        <div style={{ flex: 1, overflowY: 'auto', background: '#090d16', border: '1px solid #1f2937', borderRadius: '8px', padding: '1rem', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#9ca3af', fontFamily: 'monospace' }}>// PostgreSQL `vaults` table record:</span>
            <button
              onClick={() => copyToClipboard(rawJson, 'raw-data', 'generic')}
              style={{ background: '#1f2937', border: 'none', color: '#d1d5db', padding: '0.3rem 0.6rem', borderRadius: '4px', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              {copiedId === 'raw-data' ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
              {copiedId === 'raw-data' ? 'Copied' : 'Copy JSON'}
            </button>
          </div>
          <pre style={{ margin: 0, fontFamily: 'monospace', fontSize: '0.8rem', color: '#38bdf8', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {rawJson}
          </pre>
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            style={{ padding: '0.6rem 1.25rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
