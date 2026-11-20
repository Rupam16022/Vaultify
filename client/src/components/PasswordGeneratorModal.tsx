import React, { useState, useEffect } from 'react';
import { generatePassword, sha1 } from '../lib/crypto';
import { useClipboard } from '../hooks/useClipboard';
import { X, RefreshCw, Copy, Check, ShieldCheck, ShieldAlert } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onSelectPassword?: (password: string) => void;
}

export const PasswordGeneratorModal: React.FC<Props> = ({ isOpen, onClose, onSelectPassword }) => {
  const [length, setLength] = useState(20);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);

  const [password, setPassword] = useState('');
  const [hibpStatus, setHibpStatus] = useState<'idle' | 'checking' | 'clean' | 'breached'>('idle');
  const [breachCount, setBreachCount] = useState<number>(0);

  const { copyToClipboard, copiedId, secondsRemaining } = useClipboard();

  const handleGenerate = () => {
    try {
      const pwd = generatePassword({
        length,
        includeUppercase: includeUpper,
        includeLowercase: includeLower,
        includeNumbers: includeNumbers,
        includeSymbols: includeSymbols,
      });
      setPassword(pwd);
      checkPwnedPassword(pwd);
    } catch {
      // Ignored if invalid combination
    }
  };

  // HaveIBeenPwned k-Anonymity check
  const checkPwnedPassword = async (pwd: string) => {
    try {
      setHibpStatus('checking');
      const hash = await sha1(pwd);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!res.ok) {
        setHibpStatus('idle');
        return;
      }

      const text = await res.text();
      const lines = text.split('\n');
      let foundCount = 0;

      for (const line of lines) {
        const [hashSuffix, count] = line.trim().split(':');
        if (hashSuffix && hashSuffix.toUpperCase() === suffix.toUpperCase()) {
          foundCount = parseInt(count, 10);
          break;
        }
      }

      if (foundCount > 0) {
        setHibpStatus('breached');
        setBreachCount(foundCount);
      } else {
        setHibpStatus('clean');
      }
    } catch {
      setHibpStatus('idle');
    }
  };

  useEffect(() => {
    if (isOpen) {
      handleGenerate();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
      <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '14px', width: '100%', maxWidth: '480px', padding: '1.75rem', color: '#f9fafb', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6)' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0 }}>Unbiased Password Generator</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', padding: '0.25rem' }}>
            <X size={20} />
          </button>
        </div>

        {/* Display */}
        <div style={{ background: '#090d16', border: '1px solid #1f2937', borderRadius: '8px', padding: '1rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
          <span style={{ fontFamily: 'monospace', fontSize: '1.1rem', wordBreak: 'break-all', color: '#38bdf8' }}>
            {password}
          </span>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={handleGenerate}
              title="Regenerate"
              style={{ background: '#1f2937', border: 'none', color: '#9ca3af', padding: '0.5rem', borderRadius: '6px', cursor: 'pointer' }}
            >
              <RefreshCw size={18} />
            </button>
            <button
              onClick={() => copyToClipboard(password, 'gen-pwd', 'password')}
              title="Copy to Clipboard"
              style={{ background: copiedId === 'gen-pwd' ? '#16a34a' : '#2563eb', border: 'none', color: '#fff', padding: '0.5rem 0.75rem', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.85rem', fontWeight: 600 }}
            >
              {copiedId === 'gen-pwd' ? <Check size={16} /> : <Copy size={16} />}
              {copiedId === 'gen-pwd' ? `Copied (${secondsRemaining}s)` : 'Copy'}
            </button>
          </div>
        </div>

        {/* HIBP Breach Badge */}
        <div style={{ marginBottom: '1.25rem' }}>
          {hibpStatus === 'clean' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#34d399', fontSize: '0.8rem' }}>
              <ShieldCheck size={16} /> 0 known breach occurrences (HaveIBeenPwned k-Anonymity verified)
            </div>
          )}
          {hibpStatus === 'breached' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#f87171', fontSize: '0.8rem' }}>
              <ShieldAlert size={16} /> Warning: Seen {breachCount.toLocaleString()} times in known data breaches!
            </div>
          )}
        </div>

        {/* Controls */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            <span>Length: {length}</span>
          </div>
          <input
            type="range"
            min={8}
            max={64}
            value={length}
            onChange={(e) => {
              setLength(Number(e.target.value));
              handleGenerate();
            }}
            style={{ width: '100%', accentColor: '#2563eb' }}
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1.5rem', fontSize: '0.85rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={includeUpper} onChange={(e) => { setIncludeUpper(e.target.checked); handleGenerate(); }} />
            Uppercase (A-Z)
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={includeLower} onChange={(e) => { setIncludeLower(e.target.checked); handleGenerate(); }} />
            Lowercase (a-z)
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={includeNumbers} onChange={(e) => { setIncludeNumbers(e.target.checked); handleGenerate(); }} />
            Numbers (0-9)
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={includeSymbols} onChange={(e) => { setIncludeSymbols(e.target.checked); handleGenerate(); }} />
            Symbols (!@#$...)
          </label>
        </div>

        {/* Footer Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          <button
            onClick={onClose}
            style={{ padding: '0.6rem 1rem', background: '#1f2937', color: '#9ca3af', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
          >
            Close
          </button>
          {onSelectPassword && (
            <button
              onClick={() => {
                onSelectPassword(password);
                onClose();
              }}
              style={{ padding: '0.6rem 1.25rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
            >
              Use This Password
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
