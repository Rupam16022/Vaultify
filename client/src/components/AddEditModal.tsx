import React, { useState, useEffect } from 'react';
import { VaultItem } from '../features/vault/vaultSlice';
import { generatePassword, sha1 } from '../lib/crypto';
import { X, Key, RefreshCw, Eye, EyeOff, ShieldCheck, ShieldAlert, Sparkles } from 'lucide-react';

interface Props {
  isOpen: boolean;
  item: VaultItem | null;
  onClose: () => void;
  onSave: (item: VaultItem) => void;
}

export const AddEditModal: React.FC<Props> = ({ isOpen, item, onClose, onSave }) => {
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState<'login' | 'card' | 'note'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [notes, setNotes] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Breach check state
  const [hibpStatus, setHibpStatus] = useState<'idle' | 'checking' | 'clean' | 'breached'>('idle');
  const [breachCount, setBreachCount] = useState<number>(0);

  useEffect(() => {
    if (item) {
      setTitle(item.title || '');
      setCategory(item.category || 'login');
      setUsername(item.username || '');
      setPassword(item.password || '');
      setUrl(item.url || '');
      setNotes(item.notes || '');
      setHibpStatus('idle');
    } else {
      setTitle('');
      setCategory('login');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
      setHibpStatus('idle');
    }
  }, [item, isOpen]);

  // HIBP k-Anonymity check
  const handleCheckBreach = async () => {
    if (!password) return;
    try {
      setHibpStatus('checking');
      const hash = await sha1(password);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!res.ok) {
        setHibpStatus('idle');
        return;
      }

      const text = await res.text();
      const lines = text.split('\n');
      let found = 0;

      for (const line of lines) {
        const [hashSuffix, count] = line.trim().split(':');
        if (hashSuffix && hashSuffix.toUpperCase() === suffix.toUpperCase()) {
          found = parseInt(count, 10);
          break;
        }
      }

      if (found > 0) {
        setHibpStatus('breached');
        setBreachCount(found);
      } else {
        setHibpStatus('clean');
      }
    } catch {
      setHibpStatus('idle');
    }
  };

  const handleQuickGenerate = () => {
    const newPwd = generatePassword({ length: 22 });
    setPassword(newPwd);
    setHibpStatus('idle');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;

    const savedItem: VaultItem = {
      id: item ? item.id : (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : `item_${Date.now()}`),
      title: title.trim(),
      category,
      username: username.trim(),
      password: password,
      url: url.trim(),
      notes: notes.trim(),
      createdAt: item ? item.createdAt : new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    onSave(savedItem);
  };

  if (!isOpen) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
      <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '14px', width: '100%', maxWidth: '520px', padding: '1.75rem', color: '#f9fafb', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6)', maxHeight: '90vh', overflowY: 'auto' }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>
            {item ? 'Edit Vault Item' : 'New Vault Item'}
          </h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {/* Category Selector */}
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
            {(['login', 'card', 'note'] as const).map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setCategory(cat)}
                style={{
                  flex: 1,
                  padding: '0.45rem',
                  borderRadius: '6px',
                  border: 'none',
                  background: category === cat ? '#2563eb' : '#1f2937',
                  color: category === cat ? '#fff' : '#9ca3af',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                }}
              >
                {cat === 'login' ? 'Login Credential' : cat === 'card' ? 'Payment Card' : 'Secure Note'}
              </button>
            ))}
          </div>

          {/* Title */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem' }}>
              Title / Service Name *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. GitHub, AWS, Google"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              style={{ width: '100%', padding: '0.65rem 0.8rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem', boxSizing: 'border-box' }}
            />
          </div>

          {/* URL */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem' }}>
              Website URL
            </label>
            <input
              type="url"
              placeholder="https://example.com/login"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              style={{ width: '100%', padding: '0.65rem 0.8rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem', boxSizing: 'border-box' }}
            />
          </div>

          {/* Username / Email */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem' }}>
              Username / Email
            </label>
            <input
              type="text"
              placeholder="user@example.com"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ width: '100%', padding: '0.65rem 0.8rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem', boxSizing: 'border-box' }}
            />
          </div>

          {/* Password */}
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db' }}>
                Password / Secret
              </label>
              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <button
                  type="button"
                  onClick={handleQuickGenerate}
                  style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem', fontWeight: 600 }}
                >
                  <Sparkles size={13} /> Quick Generate
                </button>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                >
                  {showPassword ? <EyeOff size={13} /> : <Eye size={13} />} {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                placeholder="Password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setHibpStatus('idle');
                }}
                style={{ flex: 1, padding: '0.65rem 0.8rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem', fontFamily: showPassword ? 'monospace' : 'inherit' }}
              />
              <button
                type="button"
                onClick={handleCheckBreach}
                disabled={!password || hibpStatus === 'checking'}
                title="Check HaveIBeenPwned breach database"
                style={{ padding: '0.65rem 0.85rem', background: '#1f2937', border: '1px solid #374151', color: '#9ca3af', borderRadius: '6px', cursor: password ? 'pointer' : 'not-allowed', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem', whiteSpace: 'nowrap' }}
              >
                {hibpStatus === 'checking' ? <RefreshCw className="animate-spin" size={14} /> : 'Check Breach'}
              </button>
            </div>

            {/* Breach check indicator */}
            {hibpStatus === 'clean' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#34d399', fontSize: '0.75rem', marginTop: '0.35rem' }}>
                <ShieldCheck size={14} /> No breaches found in HaveIBeenPwned database.
              </div>
            )}
            {hibpStatus === 'breached' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#f87171', fontSize: '0.75rem', marginTop: '0.35rem' }}>
                <ShieldAlert size={14} /> Warning: This password was exposed {breachCount.toLocaleString()} times in public data breaches!
              </div>
            )}
          </div>

          {/* Notes */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#d1d5db', marginBottom: '0.35rem' }}>
              Secure Notes (Encrypted)
            </label>
            <textarea
              rows={3}
              placeholder="Backup codes, PINs, security questions..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              style={{ width: '100%', padding: '0.65rem 0.8rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.85rem', boxSizing: 'border-box' }}
            />
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button
              type="button"
              onClick={onClose}
              style={{ padding: '0.65rem 1.25rem', background: '#1f2937', color: '#9ca3af', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              style={{ padding: '0.65rem 1.5rem', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 700, fontSize: '0.85rem' }}
            >
              {item ? 'Save Changes' : 'Add to Vault'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
