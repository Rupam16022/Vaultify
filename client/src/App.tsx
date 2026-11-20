import React, { useState, useEffect } from 'react';
import { Provider, useSelector } from 'react-redux';
import { store, RootState } from './store';
import { AuthScreen } from './components/AuthScreen';
import { VaultDashboard } from './components/VaultDashboard';
import { CryptoTestPage } from './pages/CryptoTestPage';
import { Shield, ExternalLink } from 'lucide-react';

const MainView: React.FC = () => {
  const [currentPath, setCurrentPath] = useState(window.location.pathname);
  const isAuthenticated = useSelector((state: RootState) => state.auth.isAuthenticated);

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
        <nav style={{ background: '#0f172a', padding: '0.75rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b' }}>
          <span style={{ color: '#fff', fontWeight: 700, fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={20} color="#38bdf8" /> Vaultify
          </span>
          <button
            onClick={() => navigate('/')}
            style={{ background: 'transparent', border: '1px solid #334155', color: '#94a3b8', padding: '0.4rem 0.8rem', borderRadius: '4px', cursor: 'pointer', fontSize: '0.85rem' }}
          >
            ← Return to Vault
          </button>
        </nav>
        <CryptoTestPage />
      </div>
    );
  }

  if (isAuthenticated) {
    return <VaultDashboard />;
  }

  return (
    <div>
      <div style={{ background: '#0f172a', borderBottom: '1px solid #1e293b', padding: '0.6rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
        <span style={{ color: '#94a3b8' }}>
          Production Zero-Knowledge Architecture: Master Password never leaves client memory.
        </span>
        <button
          onClick={() => navigate('/crypto-test')}
          style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem' }}
        >
          Open Crypto Test Suite <ExternalLink size={12} />
        </button>
      </div>
      <AuthScreen />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <Provider store={store}>
      <MainView />
    </Provider>
  );
};
