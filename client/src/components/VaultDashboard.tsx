import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { RootState, AppDispatch } from '../store';
import { logout } from '../features/auth/authSlice';
import { saveVault, clearVault, VaultItem } from '../features/vault/vaultSlice';
import { useClipboard } from '../hooks/useClipboard';
import { useInactivityTimer } from '../hooks/useInactivityTimer';
import { sha1 } from '../lib/crypto';
import {
  Lock,
  Unlock,
  Plus,
  Search,
  Key,
  Copy,
  Check,
  Eye,
  EyeOff,
  ExternalLink,
  Edit2,
  Trash2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Database,
  Smartphone,
  LogOut,
  Sparkles,
  CreditCard,
  FileText,
  Clock,
  RefreshCw,
} from 'lucide-react';

import { AddEditModal } from './AddEditModal';
import { PasswordGeneratorModal } from './PasswordGeneratorModal';
import { RawDataModal } from './RawDataModal';
import { TwoFactorModal } from './TwoFactorModal';

export const VaultDashboard: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const user = useSelector((state: RootState) => state.auth.user);
  const { items, status, version } = useSelector((state: RootState) => state.vault);

  // Hook 1: 5-minute inactivity auto-lock
  useInactivityTimer();

  // Hook 2: Secure clipboard with 30-second auto-clear
  const { copyToClipboard, copiedId, secondsRemaining } = useClipboard();

  // UI State
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState<'all' | 'login' | 'card' | 'note'>('all');
  const [revealedPasswords, setRevealedPasswords] = useState<Record<string, boolean>>({});

  // Modals state
  const [isAddEditOpen, setIsAddEditOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null);
  const [isGeneratorOpen, setIsGeneratorOpen] = useState(false);
  const [isRawDataOpen, setIsRawDataOpen] = useState(false);
  const [isTwoFactorOpen, setIsTwoFactorOpen] = useState(false);

  // Per-item breach status cache
  const [breachCache, setBreachCache] = useState<Record<string, { status: 'clean' | 'breached'; count: number }>>({});
  const [checkingBreachId, setCheckingBreachId] = useState<string | null>(null);

  const toggleReveal = (id: string) => {
    setRevealedPasswords((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleLogout = () => {
    dispatch(clearVault());
    dispatch(logout());
  };

  const handleSaveItem = async (savedItem: VaultItem) => {
    let updatedItems: VaultItem[];
    if (editingItem) {
      updatedItems = items.map((i) => (i.id === savedItem.id ? savedItem : i));
    } else {
      updatedItems = [savedItem, ...items];
    }
    await dispatch(saveVault(updatedItems));
    setIsAddEditOpen(false);
    setEditingItem(null);
  };

  const handleDeleteItem = async (id: string) => {
    if (window.confirm('Are you sure you want to delete this item?')) {
      const updatedItems = items.filter((i) => i.id !== id);
      await dispatch(saveVault(updatedItems));
    }
  };

  // Run HIBP k-Anonymity check for a specific item
  const checkItemBreach = async (id: string, pwd: string) => {
    if (!pwd) return;
    try {
      setCheckingBreachId(id);
      const hash = await sha1(pwd);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!res.ok) return;

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

      setBreachCache((prev) => ({
        ...prev,
        [id]: { status: found > 0 ? 'breached' : 'clean', count: found },
      }));
    } catch {
      // Ignored
    } finally {
      setCheckingBreachId(null);
    }
  };

  // Filter items by category and search
  const filteredItems = items.filter((item) => {
    const matchesCategory = activeCategory === 'all' || item.category === activeCategory;
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      item.title.toLowerCase().includes(q) ||
      item.username.toLowerCase().includes(q) ||
      item.url.toLowerCase().includes(q) ||
      (item.notes && item.notes.toLowerCase().includes(q));
    return matchesCategory && matchesSearch;
  });

  return (
    <div style={{ minHeight: '100vh', background: '#090d16', color: '#f9fafb', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      
      {/* Top Navigation */}
      <header style={{ borderBottom: '1px solid #1f2937', background: '#111827', padding: '0.85rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ background: '#2563eb', padding: '0.45rem', borderRadius: '8px', display: 'flex' }}>
            <Lock size={20} color="#fff" />
          </div>
          <div>
            <span style={{ fontSize: '1.15rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.02em' }}>Vaultify</span>
            <span style={{ marginLeft: '0.5rem', fontSize: '0.7rem', background: '#1e3a8a', color: '#93c5fd', padding: '0.15rem 0.45rem', borderRadius: '999px', fontWeight: 600 }}>Zero-Knowledge (AES-256-GCM)</span>
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', background: '#1f2937', padding: '0.3rem 0.6rem', borderRadius: '6px', fontSize: '0.75rem', color: '#9ca3af' }}>
            <Clock size={13} color="#60a5fa" /> Auto-Lock: 5m
          </div>

          <button
            onClick={() => setIsRawDataOpen(true)}
            style={{ background: '#1f2937', border: '1px solid #374151', color: '#38bdf8', padding: '0.4rem 0.75rem', borderRadius: '6px', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Database size={14} /> View Raw Data
          </button>

          <button
            onClick={() => setIsGeneratorOpen(true)}
            style={{ background: '#1f2937', border: '1px solid #374151', color: '#d1d5db', padding: '0.4rem 0.75rem', borderRadius: '6px', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Sparkles size={14} color="#f59e0b" /> Generator
          </button>

          <button
            onClick={() => setIsTwoFactorOpen(true)}
            style={{ background: '#1f2937', border: '1px solid #374151', color: '#d1d5db', padding: '0.4rem 0.75rem', borderRadius: '6px', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Smartphone size={14} color="#10b981" /> 2FA
          </button>

          <button
            onClick={handleLogout}
            style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', color: '#f87171', padding: '0.4rem 0.75rem', borderRadius: '6px', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <LogOut size={14} /> Lock & Exit
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ maxWidth: '1080px', margin: '2rem auto', padding: '0 1.25rem' }}>
        
        {/* Top Bar: Search, Category Filter, and Add Button */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.5rem' }}>
          
          {/* Search */}
          <div style={{ position: 'relative', flex: 1, minWidth: '260px', maxWidth: '420px' }}>
            <Search size={16} color="#6b7280" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              placeholder="Search vault items..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: '100%', padding: '0.6rem 0.75rem 0.6rem 2.25rem', background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', color: '#fff', fontSize: '0.875rem', boxSizing: 'border-box' }}
            />
          </div>

          {/* Category Tabs */}
          <div style={{ display: 'flex', background: '#111827', padding: '0.25rem', borderRadius: '8px', border: '1px solid #1f2937' }}>
            {(['all', 'login', 'card', 'note'] as const).map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                style={{
                  padding: '0.4rem 0.75rem',
                  borderRadius: '6px',
                  border: 'none',
                  background: activeCategory === cat ? '#2563eb' : 'transparent',
                  color: activeCategory === cat ? '#fff' : '#9ca3af',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                }}
              >
                {cat === 'all' ? 'All Items' : cat === 'login' ? 'Logins' : cat === 'card' ? 'Cards' : 'Notes'}
              </button>
            ))}
          </div>

          {/* New Item Button */}
          <button
            onClick={() => { setEditingItem(null); setIsAddEditOpen(true); }}
            style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '0.6rem 1.25rem', borderRadius: '8px', fontWeight: 700, fontSize: '0.875rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem', boxShadow: '0 4px 6px -1px rgba(37, 99, 235, 0.3)' }}
          >
            <Plus size={16} /> New Item
          </button>
        </div>

        {/* Saving / Loading Indicator */}
        {status === 'saving' && (
          <div style={{ background: '#1e3a8a', color: '#93c5fd', padding: '0.5rem 1rem', borderRadius: '6px', fontSize: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw className="animate-spin" size={14} /> Encrypting with AES-256-GCM and saving to database...
          </div>
        )}

        {/* Vault Items List */}
        {filteredItems.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '4rem 1rem', background: '#111827', border: '1px dashed #1f2937', borderRadius: '12px' }}>
            <Key size={40} color="#374151" style={{ marginBottom: '1rem' }} />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, margin: '0 0 0.5rem', color: '#d1d5db' }}>
              {items.length === 0 ? 'Your vault is currently empty' : 'No items match your search'}
            </h3>
            <p style={{ fontSize: '0.85rem', color: '#6b7280', margin: '0 0 1.25rem' }}>
              {items.length === 0 ? 'Create your first encrypted record using the button below.' : 'Try adjusting your filters or search terms.'}
            </p>
            {items.length === 0 && (
              <button
                onClick={() => { setEditingItem(null); setIsAddEditOpen(true); }}
                style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '0.6rem 1.25rem', borderRadius: '8px', fontWeight: 600, fontSize: '0.85rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
              >
                <Plus size={16} /> Add Your First Item
              </button>
            )}
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
            {filteredItems.map((item) => {
              const isRevealed = Boolean(revealedPasswords[item.id]);
              const isPasswordCopied = copiedId === `pwd-${item.id}`;
              const isUsernameCopied = copiedId === `user-${item.id}`;
              const breach = breachCache[item.id];

              return (
                <div
                  key={item.id}
                  style={{
                    background: '#111827',
                    border: '1px solid #1f2937',
                    borderRadius: '12px',
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.2)',
                  }}
                >
                  <div>
                    {/* Item Header */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <div style={{ background: '#1f2937', padding: '0.4rem', borderRadius: '6px', color: '#38bdf8' }}>
                          {item.category === 'login' ? <Key size={16} /> : item.category === 'card' ? <CreditCard size={16} /> : <FileText size={16} />}
                        </div>
                        <div>
                          <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: '#f3f4f6' }}>{item.title}</h4>
                          {item.url && (
                            <a
                              href={item.url.startsWith('http') ? item.url : `https://${item.url}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ fontSize: '0.75rem', color: '#38bdf8', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '0.2rem', marginTop: '0.1rem' }}
                            >
                              {item.url.replace(/^https?:\/\//, '').split('/')[0]} <ExternalLink size={11} />
                            </a>
                          )}
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: '0.25rem' }}>
                        <button
                          onClick={() => { setEditingItem(item); setIsAddEditOpen(true); }}
                          title="Edit"
                          style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', padding: '0.3rem', borderRadius: '4px' }}
                        >
                          <Edit2 size={15} />
                        </button>
                        <button
                          onClick={() => handleDeleteItem(item.id)}
                          title="Delete"
                          style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', padding: '0.3rem', borderRadius: '4px' }}
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </div>

                    {/* Username */}
                    {item.username && (
                      <div style={{ background: '#090d16', border: '1px solid #1f2937', borderRadius: '6px', padding: '0.5rem 0.75rem', marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.8rem', color: '#9ca3af', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.username}
                        </span>
                        <button
                          onClick={() => copyToClipboard(item.username, `user-${item.id}`, 'username')}
                          title="Copy Username"
                          style={{ background: 'none', border: 'none', color: isUsernameCopied ? '#34d399' : '#9ca3af', cursor: 'pointer', padding: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.7rem' }}
                        >
                          {isUsernameCopied ? <Check size={14} /> : <Copy size={14} />}
                          {isUsernameCopied ? 'Copied' : ''}
                        </button>
                      </div>
                    )}

                    {/* Password */}
                    {item.password && (
                      <div style={{ background: '#090d16', border: '1px solid #1f2937', borderRadius: '6px', padding: '0.5rem 0.75rem', marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.85rem', fontFamily: isRevealed ? 'monospace' : 'inherit', color: isRevealed ? '#38bdf8' : '#9ca3af', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {isRevealed ? item.password : '••••••••••••••••'}
                        </span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                          <button
                            onClick={() => toggleReveal(item.id)}
                            title={isRevealed ? 'Hide Password' : 'Show Password'}
                            style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', padding: '0.2rem' }}
                          >
                            {isRevealed ? <EyeOff size={14} /> : <Eye size={14} />}
                          </button>
                          <button
                            onClick={() => copyToClipboard(item.password, `pwd-${item.id}`, 'password')}
                            title="Copy Password (Auto-clears in 30s)"
                            style={{
                              background: isPasswordCopied ? '#16a34a' : '#1f2937',
                              border: 'none',
                              color: '#fff',
                              borderRadius: '4px',
                              padding: '0.25rem 0.5rem',
                              cursor: 'pointer',
                              fontSize: '0.7rem',
                              fontWeight: 600,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.25rem',
                            }}
                          >
                            {isPasswordCopied ? <Check size={13} /> : <Copy size={13} />}
                            {isPasswordCopied ? `Wipe in ${secondsRemaining}s` : 'Copy'}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Notes preview */}
                    {item.notes && (
                      <p style={{ margin: '0.5rem 0 0', fontSize: '0.75rem', color: '#6b7280', overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
                        {item.notes}
                      </p>
                    )}
                  </div>

                  {/* Card Footer: HIBP Breach Checker */}
                  {item.password && (
                    <div style={{ marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid #1f2937', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      {breach ? (
                        breach.status === 'clean' ? (
                          <span style={{ fontSize: '0.7rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <ShieldCheck size={13} /> HIBP Clean (0 Breaches)
                          </span>
                        ) : (
                          <span style={{ fontSize: '0.7rem', color: '#f87171', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <ShieldAlert size={13} /> Breached {breach.count.toLocaleString()} times!
                          </span>
                        )
                      ) : (
                        <button
                          onClick={() => checkItemBreach(item.id, item.password)}
                          disabled={checkingBreachId === item.id}
                          style={{ background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                        >
                          <Shield size={12} /> {checkingBreachId === item.id ? 'Checking...' : 'Check Breach'}
                        </button>
                      )}
                      <span style={{ fontSize: '0.65rem', color: '#4b5563' }}>
                        AES-256-GCM
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </main>

      {/* Modals */}
      <AddEditModal
        isOpen={isAddEditOpen}
        item={editingItem}
        onClose={() => { setIsAddEditOpen(false); setEditingItem(null); }}
        onSave={handleSaveItem}
      />

      <PasswordGeneratorModal
        isOpen={isGeneratorOpen}
        onClose={() => setIsGeneratorOpen(false)}
      />

      <RawDataModal
        isOpen={isRawDataOpen}
        onClose={() => setIsRawDataOpen(false)}
      />

      <TwoFactorModal
        isOpen={isTwoFactorOpen}
        onClose={() => setIsTwoFactorOpen(false)}
      />
    </div>
  );
};
