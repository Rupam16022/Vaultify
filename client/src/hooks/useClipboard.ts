import { useState, useEffect, useRef, useCallback } from 'react';

interface ClipboardState {
  copiedId: string | null;
  copiedType: 'username' | 'password' | 'generic' | null;
  secondsRemaining: number;
}

export function useClipboard() {
  const [state, setState] = useState<ClipboardState>({
    copiedId: null,
    copiedType: null,
    secondsRemaining: 0,
  });

  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const countdownRef = useRef<NodeJS.Timeout | null>(null);

  const clearTimer = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (countdownRef.current) clearInterval(countdownRef.current);
  };

  const copyToClipboard = useCallback(
    async (text: string, id: string, type: 'username' | 'password' | 'generic' = 'password') => {
      try {
        await navigator.clipboard.writeText(text);

        clearTimer();

        // Passwords auto-clear after 30 seconds
        const timeoutSeconds = type === 'password' ? 30 : 5;

        setState({
          copiedId: id,
          copiedType: type,
          secondsRemaining: timeoutSeconds,
        });

        // 1-second countdown interval
        countdownRef.current = setInterval(() => {
          setState((prev) => {
            if (prev.secondsRemaining <= 1) {
              if (countdownRef.current) clearInterval(countdownRef.current);
              return { copiedId: null, copiedType: null, secondsRemaining: 0 };
            }
            return { ...prev, secondsRemaining: prev.secondsRemaining - 1 };
          });
        }, 1000);

        // Security wipe timer: Overwrites clipboard with empty string after timeout
        timerRef.current = setTimeout(async () => {
          try {
            await navigator.clipboard.writeText('');
            console.log('[Security] Clipboard securely auto-cleared.');
          } catch {
            // Ignore clipboard write restrictions
          }
        }, timeoutSeconds * 1000);
      } catch (err) {
        console.error('Failed to copy to clipboard', err);
      }
    },
    []
  );

  useEffect(() => {
    return () => clearTimer();
  }, []);

  return {
    ...state,
    copyToClipboard,
  };
}
