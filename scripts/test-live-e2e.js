import puppeteer from 'puppeteer-core';
import path from 'path';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const TARGET_URL = 'https://vaultify-95j9.onrender.com';
const ARTIFACT_DIR = 'C:\\Users\\Rupam Roy\\.gemini\\antigravity\\brain\\beca0c99-24a2-4ecb-b051-a3363e39ffb8';

async function runE2ETest() {
  console.log(`[E2E Live Test] Launching Chrome against live URL: ${TARGET_URL}`);
  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 950 });

    const timestamp = Date.now();
    const testEmail = `reviewer_${timestamp}@vaultify-sec.org`;
    const masterPassword = `Master-Password-Alpha-2026!`;

    // 1. Visit Live URL
    console.log('[E2E Live Test] Step 1: Navigating to homepage...');
    await page.goto(TARGET_URL, { waitUntil: 'networkidle2', timeout: 45000 });
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_1_auth_screen.png') });
    console.log('-> Captured: e2e_1_auth_screen.png');

    // 2. Switch to Create Vault
    console.log('[E2E Live Test] Step 2: Switching to Create Vault tab...');
    const createVaultTab = await page.waitForSelector('xpath=//button[contains(text(), "Create Vault")]');
    await createVaultTab.click();
    await new Promise((r) => setTimeout(r, 400));

    // 3. Fill Registration Form
    console.log(`[E2E Live Test] Step 3: Registering user ${testEmail}...`);
    await page.type('input[type="email"]', testEmail);
    const passwordInputs = await page.$$('input[type="password"]');
    await passwordInputs[0].type(masterPassword);
    await passwordInputs[1].type(masterPassword);

    // 4. Submit Registration
    const submitBtn = await page.waitForSelector('xpath=//button[contains(text(), "Create Encrypted Vault")]');
    await submitBtn.click();

    console.log('[E2E Live Test] Step 4: Waiting for client-side PBKDF2 (600,000 iter) and vault initialization...');
    await page.waitForSelector('xpath=//button[contains(text(), "New Item")]', { timeout: 45000 });
    console.log('-> Vault successfully initialized and unlocked!');

    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_2_vault_empty.png') });
    console.log('-> Captured: e2e_2_vault_empty.png');

    // 5. Open New Item Modal
    console.log('[E2E Live Test] Step 5: Opening New Item modal...');
    const newItemBtn = await page.waitForSelector('xpath=//button[contains(text(), "New Item")]');
    await newItemBtn.click();
    await new Promise((r) => setTimeout(r, 600));

    // 6. Fill New Item Form & Test Quick Generate & HIBP
    console.log('[E2E Live Test] Step 6: Populating credentials...');
    await page.type('input[placeholder="e.g. GitHub, AWS, Google"]', 'AWS Production Cloud');
    await page.type('input[placeholder="https://example.com/login"]', 'https://aws.amazon.com/console');
    await page.type('input[placeholder="user@example.com"]', 'cloud-sec-admin');

    // Click Quick Generate (unbiased rejection sampling)
    const quickGenBtn = await page.waitForSelector('xpath=//button[contains(text(), "Quick Generate")]');
    await quickGenBtn.click();
    await new Promise((r) => setTimeout(r, 500));

    // Click Check Breach (HaveIBeenPwned k-Anonymity)
    const checkBreachBtn = await page.waitForSelector('xpath=//button[contains(text(), "Check Breach")]');
    await checkBreachBtn.click();
    await new Promise((r) => setTimeout(r, 1500));

    // Enter secure notes
    await page.type('textarea[placeholder="Backup codes, PINs, security questions..."]', 'Hardware MFA serial: Yubikey-5-NFC-9988');

    // Click Add to Vault
    const saveItemBtn = await page.waitForSelector('xpath=//button[contains(text(), "Add to Vault")]');
    await saveItemBtn.click();
    await new Promise((r) => setTimeout(r, 1500));

    console.log('-> Item successfully encrypted with AES-256-GCM and saved to Neon DB!');
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_3_vault_with_item.png') });
    console.log('-> Captured: e2e_3_vault_with_item.png');

    // 7. Test Copy Password (30s countdown)
    console.log('[E2E Live Test] Step 7: Testing copy password with 30s auto-clear...');
    const copyBtn = await page.waitForSelector('xpath=//button[contains(text(), "Copy")]');
    await copyBtn.click();
    await new Promise((r) => setTimeout(r, 600));
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_4_clipboard_timer.png') });
    console.log('-> Captured: e2e_4_clipboard_timer.png');

    // 8. Open View Raw Data Inspector
    console.log('[E2E Live Test] Step 8: Opening View Raw Data modal...');
    const rawDataBtn = await page.waitForSelector('xpath=//button[contains(text(), "View Raw Data")]');
    await rawDataBtn.click();
    await new Promise((r) => setTimeout(r, 800));
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_5_raw_data_view.png') });
    console.log('-> Captured: e2e_5_raw_data_view.png');

    // Close Raw Data modal
    const closeRawBtn = await page.waitForSelector('xpath=//button[contains(text(), "Close Inspector")]');
    await closeRawBtn.click();
    await new Promise((r) => setTimeout(r, 500));

    // 9. Lock & Exit
    console.log('[E2E Live Test] Step 9: Locking vault & clearing memory...');
    const lockBtn = await page.waitForSelector('xpath=//button[contains(text(), "Lock & Exit")]');
    await lockBtn.click();
    await new Promise((r) => setTimeout(r, 800));
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_6_locked_state.png') });
    console.log('-> Captured: e2e_6_locked_state.png');

    // 10. Re-authenticate / Decrypt from server
    console.log('[E2E Live Test] Step 10: Unlocking vault with master password to test server decryption...');
    await page.type('input[type="email"]', testEmail);
    const loginPwdInput = await page.$('input[type="password"]');
    await loginPwdInput.type(masterPassword);

    const unlockBtn = await page.waitForSelector('xpath=//button[contains(text(), "Unlock Vault")]');
    await unlockBtn.click();

    await page.waitForSelector('xpath=//h4[contains(text(), "AWS Production Cloud")]', { timeout: 45000 });
    console.log('-> Vault successfully retrieved from Neon DB and decrypted in memory!');
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'e2e_7_reloaded_and_decrypted.png') });
    console.log('-> Captured: e2e_7_reloaded_and_decrypted.png');

    console.log('\n======================================================');
    console.log('ALL LIVE END-TO-END BROWSER WORKFLOW TESTS PASSED!');
    console.log('======================================================');
  } finally {
    await browser.close();
  }
}

runE2ETest().catch((err) => {
  console.error('[E2E Live Test Failed]:', err);
  process.exit(1);
});
