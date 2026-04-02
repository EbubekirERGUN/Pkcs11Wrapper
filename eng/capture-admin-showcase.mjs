import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const playwrightPackageDir = process.env.SHOWCASE_PLAYWRIGHT_PACKAGE_DIR?.trim();
if (!playwrightPackageDir) {
  throw new Error('Missing required environment variable SHOWCASE_PLAYWRIGHT_PACKAGE_DIR');
}

const { chromium } = await import(pathToFileURL(path.join(playwrightPackageDir, 'index.mjs')).href);

const config = requiredConfig([
  'SHOWCASE_BASE_URL',
  'SHOWCASE_USERNAME',
  'SHOWCASE_PASSWORD',
  'SHOWCASE_DEVICE_NAME',
  'SHOWCASE_MODULE_PATH',
  'SHOWCASE_TOKEN_LABEL',
  'SHOWCASE_USER_PIN',
  'SHOWCASE_FIND_LABEL',
  'SHOWCASE_ARTIFACT_ROOT'
]);

const artifactRoot = config.SHOWCASE_ARTIFACT_ROOT;
const showcaseRoot = path.join(artifactRoot, 'showcase');
const uiDeviceName = 'SoftHSM Showcase Profile';

await mkdir(showcaseRoot, { recursive: true });

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1600, height: 1000 },
  ignoreHTTPSErrors: true
});
const page = await context.newPage();

try {
  await login(page, config);
  await captureDevices(page, config, uiDeviceName, path.join(showcaseRoot, 'devices.png'));
  await captureSlots(page, config, path.join(showcaseRoot, 'slots.png'));
  await captureDashboard(page, config, path.join(showcaseRoot, 'dashboard.png'));

  console.log(`Showcase capture completed. Artifacts: ${showcaseRoot}`);
}
finally {
  await context.close();
  await browser.close();
}

function requiredConfig(names) {
  const result = {};
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (!value) {
      throw new Error(`Missing required environment variable ${name}`);
    }

    result[name] = value;
  }

  return result;
}

async function login(page, config) {
  console.log('login');
  await page.goto(`${config.SHOWCASE_BASE_URL}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await waitForVisible(page, '[data-testid="login-username"]');
  await page.fill('[data-testid="login-username"]', config.SHOWCASE_USERNAME);
  await page.fill('[data-testid="login-password"]', config.SHOWCASE_PASSWORD);
  await Promise.all([
    page.waitForURL(new RegExp(`^${escapeRegex(config.SHOWCASE_BASE_URL.replace(/\/$/, ''))}/?$`, 'i'), { timeout: 30000 }),
    page.click('[data-testid="login-submit"]')
  ]);
  await waitForVisible(page, '[data-testid="nav-devices"]');
  await settle(page);
}

async function captureDevices(page, config, uiDeviceName, screenshotPath) {
  console.log('devices');
  await navigate(page, `${config.SHOWCASE_BASE_URL}/devices`);
  await page.fill('[data-testid="device-name"]', uiDeviceName);
  await page.fill('[data-testid="device-module-path"]', config.SHOWCASE_MODULE_PATH);
  await page.fill('[data-testid="device-token-label"]', config.SHOWCASE_TOKEN_LABEL);
  await page.fill('[data-testid="device-notes"]', 'Showcase profile captured from the fixture-backed admin runtime flow.');
  await page.click('[data-testid="device-save"]');
  await waitForText(page.locator('[data-testid="devices-status"]'), `Saved device '${uiDeviceName}'.`, 15000);
  await waitForText(page.locator('[data-testid="devices-table"]'), uiDeviceName, 15000);
  await saveScreenshot(page, screenshotPath);
}

async function captureSlots(page, config, screenshotPath) {
  console.log('slots');
  await navigate(page, `${config.SHOWCASE_BASE_URL}/slots`);
  await waitForVisible(page, '[data-testid="slots-device"]');
  await page.selectOption('[data-testid="slots-device"]', { label: config.SHOWCASE_DEVICE_NAME });
  await page.click('[data-testid="slots-load"]');
  await settle(page);
  await settle(page);
  await saveScreenshot(page, screenshotPath);
}

async function captureDashboard(page, config, screenshotPath) {
  console.log('dashboard');
  await navigate(page, `${config.SHOWCASE_BASE_URL}/`);
  await waitForText(page.locator('body'), 'Pkcs11Wrapper Admin Dashboard', 15000);
  await page.evaluate(() => window.scrollTo(0, 0));
  await settle(page);
  await page.screenshot({
    path: screenshotPath,
    clip: {
      x: 0,
      y: 0,
      width: 1600,
      height: 380
    },
    timeout: 15000
  });
}

async function navigate(page, target) {
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await settle(page);
}

async function saveScreenshot(page, screenshotPath) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await settle(page);
  await page.screenshot({ path: screenshotPath, fullPage: false, timeout: 15000 });
}

async function settle(page) {
  await page.waitForTimeout(1000);
}

async function waitForVisible(page, selector, timeout = 15000) {
  await page.locator(selector).waitFor({ state: 'visible', timeout });
}

async function waitForText(locator, expected, timeout) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    try {
      if (await locator.isVisible()) {
        const text = (await locator.textContent()) ?? '';
        if (text.toLowerCase().includes(expected.toLowerCase())) {
          return;
        }
      }
    }
    catch {
      // ignore transient re-render failures while polling
    }

    await new Promise(resolve => setTimeout(resolve, 200));
  }

  const lastText = (await locator.textContent()) ?? '';
  throw new Error(`Timed out waiting for text '${expected}'. Last text: ${lastText}`);
}

async function waitForCountAtLeast(locator, minimum, timeout) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await locator.count() >= minimum) {
      return;
    }

    await new Promise(resolve => setTimeout(resolve, 200));
  }

  throw new Error(`Timed out waiting for at least ${minimum} matching element(s).`);
}

async function waitForOptionCountAtLeast(page, selector, minimum, timeout) {
  await waitForCountAtLeast(page.locator(selector), minimum, timeout);
}

async function selectFirstNonEmptyOption(page, selectSelector) {
  const value = await page.locator(`${selectSelector} option`).evaluateAll(options => {
    const usable = options.find(option => option.value && option.value.trim().length > 0);
    return usable ? usable.value : '';
  });

  if (!value) {
    throw new Error(`No selectable option was available for ${selectSelector}`);
  }

  await page.selectOption(selectSelector, { value });
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
