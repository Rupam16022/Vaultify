import { configureStore } from '@reduxjs/toolkit';
import authReducer from '../features/auth/authSlice';
import vaultReducer from '../features/vault/vaultSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    vault: vaultReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
