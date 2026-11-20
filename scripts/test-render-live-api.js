import crypto from 'crypto';

const BASE_URL = 'https://vaultify-95j9.onrender.com';

async function runLiveApiTest() {
  console.log(`[Live Test] Testing backend endpoints on ${BASE_URL}...`);

  async function api(path, method = 'GET', body = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    });
    const data = await res.json().catch(() => null);
    return { status: res.status, data };
  }

  const testEmail = `render_live_${Date.now()}@vaultify-security.test`;
  console.log(`\n1. Fetching salt for email: ${testEmail}`);
  const saltRes = await api('/api/auth/salt', 'POST', { email: testEmail });
  console.log('-> Salt response:', saltRes);
  if (saltRes.status !== 200 || !saltRes.data.salt || saltRes.data.salt.length !== 32) {
    throw new Error('Live salt fetch failed!');
  }

  console.log('\n2. Testing registration with derived Auth Key...');
  const authKey = crypto.randomBytes(32).toString('hex');
  const regRes = await api('/api/auth/register', 'POST', {
    email: testEmail,
    salt: saltRes.data.salt,
    authKey,
  });
  console.log('-> Register response:', regRes);
  if (regRes.status !== 201 || !regRes.data.token) {
    throw new Error('Live registration failed!');
  }
  const token = regRes.data.token;

  console.log('\n3. Testing login with valid credentials...');
  const loginRes = await api('/api/auth/login', 'POST', {
    email: testEmail,
    authKey,
  });
  console.log('-> Login response:', loginRes);
  if (loginRes.status !== 200 || !loginRes.data.token) {
    throw new Error('Live login failed!');
  }

  console.log('\n4. Testing GET /api/vault on live server...');
  const initialVault = await api('/api/vault', 'GET', null, token);
  console.log('-> Initial vault:', initialVault);

  console.log('\n5. Testing PUT /api/vault (storing encrypted zero-knowledge blob)...');
  const dummyCiphertext = Buffer.from('LiveRenderEncryptedVaultDataBlob!').toString('base64');
  const dummyIv = Buffer.from('123456789012').toString('base64');
  const saveVault = await api(
    '/api/vault',
    'PUT',
    { ciphertext: dummyCiphertext, iv: dummyIv },
    token
  );
  console.log('-> Save vault response:', saveVault);
  if (saveVault.status !== 200) {
    throw new Error('Live save vault failed!');
  }

  console.log('\n6. Testing GET /api/vault (verifying zero-knowledge round-trip on Neon PostgreSQL)...');
  const verifyVault = await api('/api/vault', 'GET', null, token);
  console.log('-> Stored live vault:', verifyVault);
  if (
    verifyVault.data.ciphertext !== dummyCiphertext ||
    verifyVault.data.iv !== dummyIv
  ) {
    throw new Error('Stored live vault does not match saved payload!');
  }

  console.log('\n======================================================');
  console.log('SUCCESS: ALL PHASE 2 ENDPOINTS VERIFIED ON LIVE RENDER!');
  console.log('======================================================');
}

runLiveApiTest().catch((err) => {
  console.error('[Live Test Error]:', err);
  process.exit(1);
});
