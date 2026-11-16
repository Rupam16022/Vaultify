import http from 'http';
import { app } from '../server/dist/app.js';
import crypto from 'crypto';

async function runTests() {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  console.log(`[Integration Test] Server listening on ${baseUrl}`);

  async function req(path, method = 'GET', body = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    });
    const data = await res.json().catch(() => null);
    return { status: res.status, data };
  }

  try {
    const testEmail = `test_${Date.now()}@example.com`;
    console.log(`\n--- Test 1: Fake deterministic salt for unknown email ---`);
    const saltRes1 = await req('/api/auth/salt', 'POST', { email: testEmail });
    console.log('Salt 1:', saltRes1.data);
    if (saltRes1.status !== 200 || !saltRes1.data.salt || saltRes1.data.salt.length !== 32) {
      throw new Error('Salt test 1 failed');
    }

    console.log(`\n--- Test 2: Repeat call to verify salt determinism ---`);
    const saltRes2 = await req('/api/auth/salt', 'POST', { email: testEmail });
    if (saltRes1.data.salt !== saltRes2.data.salt) {
      throw new Error('Salt is not deterministic! User enumeration possible.');
    }
    console.log('Deterministic salt verified successfully.');

    console.log(`\n--- Test 3: Register account with Auth Key ---`);
    const userSalt = saltRes1.data.salt;
    const authKey = crypto.randomBytes(32).toString('hex'); // 64 hex chars
    const regRes = await req('/api/auth/register', 'POST', {
      email: testEmail,
      salt: userSalt,
      authKey,
    });
    console.log('Register response:', regRes.data);
    if (regRes.status !== 201 || !regRes.data.token) {
      throw new Error('Registration failed');
    }
    const token = regRes.data.token;

    console.log(`\n--- Test 4: Duplicate registration should be rejected ---`);
    const dupRes = await req('/api/auth/register', 'POST', {
      email: testEmail,
      salt: userSalt,
      authKey,
    });
    if (dupRes.status !== 409) {
      throw new Error('Duplicate registration was not rejected with 409!');
    }
    console.log('Duplicate correctly rejected with 409 Conflict.');

    console.log(`\n--- Test 5: Login with correct Auth Key ---`);
    const loginRes = await req('/api/auth/login', 'POST', {
      email: testEmail,
      authKey,
    });
    if (loginRes.status !== 200 || !loginRes.data.token) {
      throw new Error('Login with correct key failed');
    }
    console.log('Login succeeded, JWT received.');

    console.log(`\n--- Test 6: Login with invalid Auth Key ---`);
    const badKey = crypto.randomBytes(32).toString('hex');
    const badLoginRes = await req('/api/auth/login', 'POST', {
      email: testEmail,
      authKey: badKey,
    });
    if (badLoginRes.status !== 401) {
      throw new Error('Login with bad key should return 401!');
    }
    console.log('Invalid key correctly returned 401 Unauthorized.');

    console.log(`\n--- Test 7: GET /api/vault without auth ---`);
    const unauthVault = await req('/api/vault', 'GET');
    if (unauthVault.status !== 401) {
      throw new Error('Unauthenticated vault access should return 401!');
    }
    console.log('Unauthenticated access blocked (401).');

    console.log(`\n--- Test 8: GET /api/vault initial state ---`);
    const emptyVault = await req('/api/vault', 'GET', null, token);
    console.log('Initial vault:', emptyVault.data);
    if (emptyVault.status !== 200) {
      throw new Error('Failed to fetch initial vault');
    }

    console.log(`\n--- Test 9: PUT /api/vault with encrypted payload ---`);
    const fakeCiphertext = Buffer.from('EncryptedSecretVaultDataBlob123').toString('base64');
    const fakeIv = Buffer.from('123456789012').toString('base64');
    const saveRes = await req(
      '/api/vault',
      'PUT',
      { ciphertext: fakeCiphertext, iv: fakeIv },
      token
    );
    console.log('Save response:', saveRes.data);
    if (saveRes.status !== 200) {
      throw new Error('Failed to save vault');
    }

    console.log(`\n--- Test 10: GET /api/vault verify round-trip persistence ---`);
    const getVault = await req('/api/vault', 'GET', null, token);
    console.log('Stored vault:', getVault.data);
    if (getVault.data.ciphertext !== fakeCiphertext || getVault.data.iv !== fakeIv) {
      throw new Error('Retrieved vault data does not match saved payload!');
    }
    console.log('Zero-knowledge payload verified in database!');

    console.log('\n========================================');
    console.log('ALL PHASE 2 BACKEND ENDPOINTS PASSED!');
    console.log('========================================');
  } finally {
    server.close();
  }
}

runTests().catch((err) => {
  console.error('[Test Failed]:', err);
  process.exit(1);
});
