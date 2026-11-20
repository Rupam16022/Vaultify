import puppeteer from 'puppeteer-core';
import { authenticator } from 'otplib';
import path from 'path';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const TARGET_URL = 'https://vaultify-95j9.onrender.com';
const ARTIFACT_DIR = 'C:\\Users\\Rupam Roy\\.gemini\\antigravity\\brain\\beca0c99-24a2-4ecb-b051-a3363e39ffb8';

async function capture2faFlow() {
  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 950 });

    const timestamp = Date.now();
    const testEmail = `totp_ui_${timestamp}@vaultify.io`;
    const masterPassword = `Master-Password-Alpha-2026!`;

    console.log('[Browser 2FA] Registering new user...');
    await page.goto(TARGET_URL, { waitUntil: 'networkidle2', timeout: 45000 });

    const createVaultTab = await page.waitForSelector('xpath=//button[contains(text(), "Create Vault")]');
    await createVaultTab.click();
    await new Promise((r) => setTimeout(r, 400));

    await page.type('input[type="email"]', testEmail);
    const passwordInputs = await page.$$('input[type="password"]');
    await passwordInputs[0].type(masterPassword);
    await passwordInputs[1].type(masterPassword);

    const submitBtn = await page.waitForSelector('xpath=//button[contains(text(), "Create Encrypted Vault")]');
    await submitBtn.click();

    await page.waitForSelector('xpath=//button[contains(text(), "2FA")]', { timeout: 45000 });
    console.log('[Browser 2FA] Opening 2FA modal...');
    const twoFaBtn = await page.waitForSelector('xpath=//button[contains(text(), "2FA")]');
    await twoFaBtn.click();
    await new Promise((r) => setTimeout(r, 600));

    // Click Configure Authenticator App
    const configBtn = await page.waitForSelector('xpath=//button[contains(text(), "Configure Authenticator App")]');
    await configBtn.click();

    // Wait for secret key in UI
    await page.waitForSelector('img[alt="2FA QR Code"]', { timeout: 15000 });
    const secretElement = await page.waitForSelector('xpath=//div[contains(@style, "monospace")]');
    const secret = await page.evaluate((el) => el.innerText.trim(), secretElement);
    console.log(`[Browser 2FA] Scraped secret: ${secret}`);

    // Generate code
    const token = authenticator.generate(secret);
    console.log(`[Browser 2FA] Generated token: ${token}`);

    // Type code
    const codeInput = await page.waitForSelector('input[placeholder="123456"]');
    await codeInput.type(token);

    // Click Verify & Enable 2FA
    const enableBtn = await page.waitForSelector('xpath=//button[contains(text(), "Verify & Enable 2FA")]');
    await enableBtn.click();

    // Wait for One-Time Backup Recovery Codes section
    await page.waitForSelector('xpath=//*[contains(text(), "One-Time Backup Recovery Codes")]', { timeout: 15000 });
    console.log('[Browser 2FA] Backup codes successfully presented!');

    await new Promise((r) => setTimeout(r, 800));
    await page.screenshot({ path: path.join(ARTIFACT_DIR, 'live_2fa_backup_codes.png') });
    console.log('-> Captured: live_2fa_backup_codes.png');
  } finally {
    await browser.close();
  }
}

capture2faFlow().catch((err) => {
  console.error('[Browser 2FA Error]:', err);
  process.exit(1);
});
