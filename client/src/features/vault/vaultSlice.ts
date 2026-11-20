import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { api } from '../../lib/api';
import { keyStore } from '../../lib/keyStore';
import { encryptVault, decryptVault } from '../../lib/crypto';

export interface VaultItem {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  category: 'login' | 'card' | 'note';
  createdAt: string;
  updatedAt: string;
}

interface VaultState {
  items: VaultItem[];
  rawCiphertext: string | null;
  rawIv: string | null;
  version: number;
  updatedAt: string | null;
  status: 'idle' | 'loading' | 'saving' | 'error';
  errorMessage: string | null;
}

const initialState: VaultState = {
  items: [],
  rawCiphertext: null,
  rawIv: null,
  version: 0,
  updatedAt: null,
  status: 'idle',
  errorMessage: null,
};

// Async thunk to fetch encrypted blob from server and decrypt with in-memory key
export const fetchVault = createAsyncThunk(
  'vault/fetchVault',
  async (_, { rejectWithValue }) => {
    try {
      const encKey = keyStore.getKey();
      if (!encKey) {
        throw new Error('Encryption key not present in memory. Vault is locked.');
      }

      const res = await api.getVault();

      if (!res.ciphertext || !res.iv) {
        // Vault is empty
        return {
          items: [] as VaultItem[],
          ciphertext: null,
          iv: null,
          version: res.version,
          updated_at: res.updated_at,
        };
      }

      // Decrypt AES-256-GCM ciphertext in memory
      const decryptedItems = await decryptVault<VaultItem[]>(
        res.ciphertext,
        res.iv,
        encKey
      );

      return {
        items: decryptedItems,
        ciphertext: res.ciphertext,
        iv: res.iv,
        version: res.version,
        updated_at: res.updated_at,
      };
    } catch (err: unknown) {
      return rejectWithValue(err instanceof Error ? err.message : 'Failed to load vault');
    }
  }
);

// Async thunk to encrypt updated items with fresh IV and save to server
export const saveVault = createAsyncThunk(
  'vault/saveVault',
  async (items: VaultItem[], { rejectWithValue }) => {
    try {
      const encKey = keyStore.getKey();
      if (!encKey) {
        throw new Error('Encryption key not present in memory. Vault is locked.');
      }

      // Encrypt with AES-256-GCM using a freshly generated 12-byte IV
      const payload = await encryptVault(items, encKey);

      // Save encrypted blob to dumb server
      const res = await api.saveVault(payload.ciphertext, payload.iv);

      return {
        items,
        ciphertext: payload.ciphertext,
        iv: payload.iv,
        version: res.version,
        updated_at: res.updated_at,
      };
    } catch (err: unknown) {
      return rejectWithValue(err instanceof Error ? err.message : 'Failed to save vault');
    }
  }
);

export const vaultSlice = createSlice({
  name: 'vault',
  initialState,
  reducers: {
    clearVault(state) {
      state.items = [];
      state.rawCiphertext = null;
      state.rawIv = null;
      state.version = 0;
      state.updatedAt = null;
      state.status = 'idle';
      state.errorMessage = null;
    },
    clearVaultError(state) {
      state.errorMessage = null;
    },
  },
  extraReducers: (builder) => {
    builder
      // fetchVault
      .addCase(fetchVault.pending, (state) => {
        state.status = 'loading';
        state.errorMessage = null;
      })
      .addCase(fetchVault.fulfilled, (state, action) => {
        state.status = 'idle';
        state.items = action.payload.items;
        state.rawCiphertext = action.payload.ciphertext;
        state.rawIv = action.payload.iv;
        state.version = action.payload.version;
        state.updatedAt = action.payload.updated_at;
      })
      .addCase(fetchVault.rejected, (state, action) => {
        state.status = 'error';
        state.errorMessage = (action.payload as string) || 'Failed to decrypt vault';
      })
      // saveVault
      .addCase(saveVault.pending, (state) => {
        state.status = 'saving';
        state.errorMessage = null;
      })
      .addCase(saveVault.fulfilled, (state, action) => {
        state.status = 'idle';
        state.items = action.payload.items;
        state.rawCiphertext = action.payload.ciphertext;
        state.rawIv = action.payload.iv;
        state.version = action.payload.version;
        state.updatedAt = action.payload.updated_at;
      })
      .addCase(saveVault.rejected, (state, action) => {
        state.status = 'error';
        state.errorMessage = (action.payload as string) || 'Failed to encrypt and save vault';
      });
  },
});

export const { clearVault, clearVaultError } = vaultSlice.actions;
export default vaultSlice.reducer;
