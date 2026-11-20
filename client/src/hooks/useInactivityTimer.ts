import { useEffect, useRef, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { RootState, AppDispatch } from '../store';
import { logout } from '../features/auth/authSlice';
import { clearVault } from '../features/vault/vaultSlice';

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

export function useInactivityTimer() {
  const dispatch = useDispatch<AppDispatch>();
  const isAuthenticated = useSelector((state: RootState) => state.auth.isAuthenticated);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  const lockVault = useCallback(() => {
    if (isAuthenticated) {
      console.log('[Security] Inactivity timeout reached (5 minutes). Auto-locking vault.');
      dispatch(clearVault());
      dispatch(logout());
    }
  }, [isAuthenticated, dispatch]);

  const resetTimer = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    if (isAuthenticated) {
      timeoutRef.current = setTimeout(lockVault, INACTIVITY_TIMEOUT_MS);
    }
  }, [isAuthenticated, lockVault]);

  useEffect(() => {
    if (!isAuthenticated) return;

    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];

    const handleUserActivity = () => {
      resetTimer();
    };

    // Attach activity listeners
    events.forEach((evt) => window.addEventListener(evt, handleUserActivity, { passive: true }));
    resetTimer();

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      events.forEach((evt) => window.removeEventListener(evt, handleUserActivity));
    };
  }, [isAuthenticated, resetTimer]);
}
