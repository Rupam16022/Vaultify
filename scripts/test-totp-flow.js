import http from 'http';
import { app } from '../server/dist/app.js';
import { authenticator } from 'otplib';
import crypto from 'crypto';

async function runTotpTests() {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  console.log(`[TOTP Test] Server listening on ${baseUrl}`);

  async function api(path, method = 'GET', body = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  try {
    const testEmail = `totp_test_${Date.now()}@vaultify.internal`;
    const authKey = crypto.randomBytes(32).toString('hex');
    const salt = crypto.randomBytes(16).toString('hex');

    console.log('\n--- 1. Register User ---');
    const regRes = await api('/api/auth/register', 'POST', {
      email: testEmail,
      salt,
      authKey,
    });
    if (regRes.status !== 201) throw new Error('Registration failed: ' + JSON.stringify(regRes.data));
    let token = regRes.data.token;
    console.log('Registered user successfully.');

    console.log('\n--- 2. Check Initial 2FA Status ---');
    const status1 = await api('/api/auth/2fa/status', 'GET', null, token);
    console.log('Status 1:', status1.data);
    if (status1.data.enabled !== false) throw new Error('2FA should initially be disabled');

    console.log('\n--- 3. Setup 2FA ---');
    const setupRes = await api('/api/auth/2fa/setup', 'POST', null, token);
    console.log('Setup response keys:', Object.keys(setupRes.data));
    const secret = setupRes.data.secret;
    if (!secret || !setupRes.data.qrCode) throw new Error('Setup did not return secret and qrCode');

    console.log('\n--- 4. Verify & Enable 2FA ---');
    const totpToken = authenticator.generate(secret);
    const verifyRes = await api('/api/auth/2fa/verify', 'POST', { code: totpToken }, token);
    console.log('Verify response:', verifyRes.data);
    if (!verifyRes.data.enabled || !Array.isArray(verifyRes.data.backupCodes) || verifyRes.data.backupCodes.length !== 8) {
      throw new Error('Verify failed to enable 2FA or generate 8 backup codes');
    }
    const backupCodes = verifyRes.data.backupCodes;
    console.log(`Generated ${backupCodes.length} backup codes:`, backupCodes);

    console.log('\n--- 5. Login Attempt (Should Require 2FA) ---');
    const loginRes = await api('/api/auth/login', 'POST', { email: testEmail, authKey });
    console.log('Login response:', loginRes.data);
    if (!loginRes.data.require2fa || !loginRes.data.preAuthToken) {
      throw new Error('Login did not require 2FA step-up!');
    }
    const preAuthToken = loginRes.data.preAuthToken;

    console.log('\n--- 6. Step-Up 2FA Verification (Using TOTP Code) ---');
    const freshToken = authenticator.generate(secret);
    const stepUpRes = await api('/api/auth/2fa/verify', 'POST', { token: freshToken }, preAuthToken);
    console.log('Step-up TOTP response:', stepUpRes.data);
    if (stepUpRes.status !== 200 || !stepUpRes.data.token) {
      throw new Error('Step-up verification failed with TOTP code');
    }
    token = stepUpRes.data.token;
    console.log('Step-up with TOTP succeeded! Full JWT received.');

    console.log('\n--- 7. Login Step-Up (Using Backup Recovery Code) ---');
    const loginRes2 = await api('/api/auth/login', 'POST', { email: testEmail, authKey });
    const preAuthToken2 = loginRes2.data.preAuthToken;
    const backupCodeToUse = backupCodes[0];
    console.log(`Testing backup code: ${backupCodeToUse}`);

    const backupStepUp = await api('/api/auth/2fa/verify', 'POST', { code: backupCodeToUse }, preAuthToken2);
    console.log('Backup code step-up response:', backupStepUp.data);
    if (backupStepUp.status !== 200 || !backupStepUp.data.token) {
      throw new Error('Step-up verification failed with backup code');
    }
    console.log('Step-up with Backup Code succeeded!');

    console.log('\n--- 8. Verify Used Backup Code is Consumed ---');
    const statusAfterBackup = await api('/api/auth/2fa/status', 'GET', null, backupStepUp.data.token);
    console.log('Status after using backup code:', statusAfterBackup.data);
    if (statusAfterBackup.data.backupCodesRemaining !== 7) {
      throw new Error(`Expected 7 backup codes remaining, got: ${statusAfterBackup.data.backupCodesRemaining}`);
    }
    console.log('Backup code was successfully consumed atomically!');

    console.log('\n--- 9. Check Audit Logs ---');
    const auditRes = await api('/api/auth/audit', 'GET', null, backupStepUp.data.token);
    console.log(`Audit log records found: ${auditRes.data.logs.length}`);
    const eventTypes = auditRes.data.logs.map((l) => l.event_type);
    console.log('Recorded event types:', eventTypes);

    console.log('\n========================================');
    console.log('ALL TOTP & DATABASE FEATURE TESTS PASSED!');
    console.log('========================================');
  } finally {
    server.close();
  }
}

runTotpTests().catch((err) => {
  console.error('[TOTP Test Failed]:', err);
  process.exit(1);
});
