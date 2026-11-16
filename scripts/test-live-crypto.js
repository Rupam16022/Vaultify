import puppeteer from 'puppeteer-core';
import path from 'path';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const TARGET_URL = 'https://vaultify-95j9.onrender.com/crypto-test';
const SCREENSHOT_PATH = 'C:\\Users\\Rupam Roy\\.gemini\\antigravity\\brain\\beca0c99-24a2-4ecb-b051-a3363e39ffb8\\phase1_live_crypto_test_interactive.png';

async function runLiveTest() {
  console.log(`[Browser Agent] Launching Chrome against live URL: ${TARGET_URL}`);
  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 1600 });

    console.log('[Browser Agent] Navigating...');
    await page.goto(TARGET_URL, { waitUntil: 'networkidle2', timeout: 30000 });

    console.log('[Browser Agent] Clicking "New Salt"...');
    const newSaltBtn = await page.waitForSelector('xpath=//button[contains(text(), "New Salt")]');
    await newSaltBtn.click();
    await new Promise((r) => setTimeout(r, 500));

    console.log('[Browser Agent] Clicking "Derive Keys (PBKDF2 + HKDF)"...');
    const deriveBtn = await page.waitForSelector('xpath=//button[contains(text(), "Derive Keys")]');
    await deriveBtn.click();

    console.log('[Browser Agent] Waiting for PBKDF2 (600,000 iterations)...');
    await page.waitForSelector('xpath=//*[contains(text(), "Derived Subkeys")]', { timeout: 30000 });
    console.log('[Browser Agent] Keys successfully derived!');

    console.log('[Browser Agent] Clicking "Encrypt (AES-256-GCM)"...');
    const encryptBtn = await page.waitForSelector('xpath=//button[contains(text(), "Encrypt (AES-256-GCM)")]');
    await encryptBtn.click();
    await new Promise((r) => setTimeout(r, 600));

    console.log('[Browser Agent] Clicking "Decrypt (Same Key)"...');
    const decryptBtn = await page.waitForSelector('xpath=//button[contains(text(), "Decrypt (Same Key)")]');
    await decryptBtn.click();
    await new Promise((r) => setTimeout(r, 600));

    console.log('[Browser Agent] Clicking "Test Wrong Key"...');
    const wrongKeyBtn = await page.waitForSelector('xpath=//button[contains(text(), "Test Wrong Key")]');
    await wrongKeyBtn.click();
    await new Promise((r) => setTimeout(r, 1500)); // derivation with wrong key

    console.log('[Browser Agent] Clicking "Test Tampered Ciphertext"...');
    const tamperBtn = await page.waitForSelector('xpath=//button[contains(text(), "Test Tampered Ciphertext")]');
    await tamperBtn.click();
    await new Promise((r) => setTimeout(r, 600));

    console.log('[Browser Agent] Clicking "Generate Unbiased Password"...');
    const genPwdBtn = await page.waitForSelector('xpath=//button[contains(text(), "Generate Unbiased Password")]');
    await genPwdBtn.click();
    await new Promise((r) => setTimeout(r, 600));

    console.log(`[Browser Agent] Capturing full-page screenshot to ${SCREENSHOT_PATH}...`);
    await page.screenshot({ path: SCREENSHOT_PATH, fullPage: true });
    console.log('[Browser Agent] Screenshot successfully saved!');
  } finally {
    await browser.close();
  }
}

runLiveTest().catch((err) => {
  console.error('[Browser Agent] Error:', err);
  process.exit(1);
});
