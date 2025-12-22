import { chromium, FullConfig } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';

const DEFAULT_BWAPP_URL = 'http://localhost:8080';
const STORAGE_STATE_PATH = path.join(__dirname, 'storage-states', 'bwapp-auth.json');

async function ensureDirExists(filePath: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
}

async function loginToBwapp(baseUrl: string, storageStatePath: string = STORAGE_STATE_PATH): Promise<void> {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`${baseUrl}/login.php`);
  await page.fill('input[name="login"]', process.env['BWAPP_USER'] ?? 'bee');
  await page.fill('input[name="password"]', process.env['BWAPP_PASSWORD'] ?? 'bug');
  await page.selectOption('select[name="security_level"]', process.env['BWAPP_SECURITY_LEVEL'] ?? '0');
  await page.click('[name="form"]');
  await page.waitForURL('**/portal.php');

  await ensureDirExists(storageStatePath);
  await context.storageState({ path: storageStatePath });

  await browser.close();
}

export async function ensureBwappAuthState(
  baseUrl: string = DEFAULT_BWAPP_URL,
  storageStatePath: string = STORAGE_STATE_PATH
): Promise<string> {
  try {
    await fs.access(storageStatePath);
    return storageStatePath;
  } catch {
    await loginToBwapp(baseUrl, storageStatePath);
    return storageStatePath;
  }
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  const bwappUrl = process.env['BWAPP_URL'] ?? DEFAULT_BWAPP_URL;
  await ensureBwappAuthState(bwappUrl, STORAGE_STATE_PATH);
}
