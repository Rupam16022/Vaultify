/**
 * HTTP API client for Vaultify backend endpoints.
 * Operates purely with ephemeral in-memory tokens.
 */

let inMemoryToken: string | null = null;

export const setApiToken = (token: string | null) => {
  inMemoryToken = token;
};

export const getApiToken = () => inMemoryToken;

export interface SaltResponse {
  salt: string;
}

export interface AuthResponse {
  token?: string;
  user?: {
    id: string;
    email: string;
  };
  require2fa?: boolean;
  preAuthToken?: string;
}

export interface VaultResponse {
  ciphertext: string | null;
  iv: string | null;
  version: number;
  updated_at: string | null;
}

export interface SaveVaultResponse {
  message: string;
  version: number;
  updated_at: string;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');

  if (inMemoryToken) {
    headers.set('Authorization', `Bearer ${inMemoryToken}`);
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg = (data && data.error) || (data && data.message) || `Request failed with status ${response.status}`;
    throw new Error(errorMsg);
  }

  return data as T;
}

export const api = {
  getSalt(email: string): Promise<SaltResponse> {
    return request<SaltResponse>('/api/auth/salt', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  register(email: string, salt: string, authKey: string): Promise<AuthResponse> {
    return request<AuthResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, salt, authKey }),
    });
  },

  login(email: string, authKey: string): Promise<AuthResponse> {
    return request<AuthResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, authKey }),
    });
  },

  getVault(): Promise<VaultResponse> {
    return request<VaultResponse>('/api/vault', {
      method: 'GET',
    });
  },

  saveVault(ciphertext: string, iv: string): Promise<SaveVaultResponse> {
    return request<SaveVaultResponse>('/api/vault', {
      method: 'PUT',
      body: JSON.stringify({ ciphertext, iv }),
    });
  },
};
