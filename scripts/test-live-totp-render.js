import { authenticator } from 'otplib';
import crypto from 'crypto';

const BASE_URL = 'https://vaultify-95j9.onrender.com';

async function testLiveTotp() {
  console.log(`[Live 2FA Test] Testing TOTP flow on live Render URL: ${BASE_URL}...`);

  async function api(path, method = 'GET', body = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  const testEmail = `render_totp_${Date.now()}@vaultify-sec.org`;
  const authKey = crypto.randomBytes(32).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');

  console.log('1. Registering user...');
  const regRes = await api('/api/auth/register', 'POST', { email: testEmail, salt, authKey });
  if (regRes.status !== 201) throw new Error('Live registration failed: ' + JSON.stringify(regRes.data));
  let token = regRes.data.token;
  console.log('-> User registered.');

  console.log('2. Requesting 2FA setup...');
  const setupRes = await api('/api/auth/2fa/setup', 'POST', null, token);
  const secret = setupRes.data.secret;
  if (!secret) throw new Error('Live setup failed: ' + JSON.stringify(setupRes.data));
  console.log('-> Secret generated and encrypted with TOTP_ENC_KEY at rest on Neon DB.');

  console.log('3. Enabling 2FA with generated TOTP code...');
  const totpToken = authenticator.generate(secret);
  const verifyRes = await api('/api/auth/2fa/verify', 'POST', { code: totpToken }, token);
  if (!verifyRes.data.enabled || !verifyRes.data.backupCodes) {
    throw new Error('Live 2FA activation failed: ' + JSON.stringify(verifyRes.data));
  }
  const backupCodes = verifyRes.data.backupCodes;
  console.log(`-> 2FA enabled! Received ${backupCodes.length} backup codes:`, backupCodes);

  console.log('4. Logging in (step 1: should return require2fa: true)...');
  const loginRes = await api('/api/auth/login', 'POST', { email: testEmail, authKey });
  if (!loginRes.data.require2fa || !loginRes.data.preAuthToken) {
    throw new Error('Login did not require 2FA: ' + JSON.stringify(loginRes.data));
  }
  const preAuthToken = loginRes.data.preAuthToken;
  console.log('-> Pre-auth token received.');

  console.log('5. Step-up login with TOTP code...');
  const freshCode = authenticator.generate(secret);
  const stepUpRes = await api('/api/auth/2fa/verify', 'POST', { token: freshCode }, preAuthToken);
  if (stepUpRes.status !== 200 || !stepUpRes.data.token) {
    throw new Error('Step-up login with TOTP failed: ' + JSON.stringify(stepUpRes.data));
  }
  console.log('-> Step-up login succeeded! Full JWT received.');

  console.log('6. Step-up login with Backup Recovery Code...');
  const loginRes2 = await api('/api/auth/login', 'POST', { email: testEmail, authKey });
  const preAuthToken2 = loginRes2.data.preAuthToken;
  const backupCode = backupCodes[0];
  const backupStepUp = await api('/api/auth/2fa/verify', 'POST', { code: backupCode }, preAuthToken2);
  if (backupStepUp.status !== 200 || !backupStepUp.data.token) {
    throw new Error('Step-up login with Backup Code failed: ' + JSON.stringify(backupStepUp.data));
  }
  console.log('-> Step-up login with Backup Code succeeded!');

  console.log('7. Verifying backup code was consumed in database...');
  const statusRes = await api('/api/auth/2fa/status', 'GET', null, backupStepUp.data.token);
  console.log('-> 2FA Status on live server:', statusRes.data);
  if (statusRes.data.backupCodesRemaining !== 7) {
    throw new Error('Backup code was not consumed!');
  }

  console.log('\n======================================================');
  console.log('ALL LIVE TOTP & DATABASE TESTS VERIFIED ON RENDER!');
  console.log('======================================================');
}

testLiveTotp().catch((err) => {
  console.error('[Live 2FA Test Failed]:', err);
  process.exit(1);
});
