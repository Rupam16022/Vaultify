import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { setApiToken } from '../../lib/api';
import { keyStore } from '../../lib/keyStore';

export interface UserProfile {
  id: string;
  email: string;
}

interface AuthState {
  token: string | null;
  user: UserProfile | null;
  isAuthenticated: boolean;
  isUnlocked: boolean;
  status: 'idle' | 'loading' | 'error';
  errorMessage: string | null;
}

const initialState: AuthState = {
  token: null,
  user: null,
  isAuthenticated: false,
  isUnlocked: false,
  status: 'idle',
  errorMessage: null,
};

export const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setLoading(state) {
      state.status = 'loading';
      state.errorMessage = null;
    },
    setError(state, action: PayloadAction<string>) {
      state.status = 'error';
      state.errorMessage = action.payload;
    },
    clearError(state) {
      state.errorMessage = null;
    },
    loginSuccess(
      state,
      action: PayloadAction<{ token: string; user: UserProfile }>
    ) {
      state.token = action.payload.token;
      state.user = action.payload.user;
      state.isAuthenticated = true;
      state.isUnlocked = true;
      state.status = 'idle';
      state.errorMessage = null;

      // Update API client in-memory token
      setApiToken(action.payload.token);
    },
    logout(state) {
      state.token = null;
      state.user = null;
      state.isAuthenticated = false;
      state.isUnlocked = false;
      state.status = 'idle';
      state.errorMessage = null;

      // Wipe key and token from memory
      setApiToken(null);
      keyStore.clearKey();
    },
  },
});

export const { setLoading, setError, clearError, loginSuccess, logout } = authSlice.actions;
export default authSlice.reducer;
