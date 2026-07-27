import { expect, Page, test as base } from '@playwright/test';

export { expect };

export const juiceShopUrl = (
  process.env['JUICE_SHOP_URL'] ??
  process.env['JUICESHOP_URL'] ??
  'http://localhost:3000'
).replace(/\/$/, '');

type JuiceShopFixtures = {
  targetUrl: string;
};

export const test = base.extend<JuiceShopFixtures>({
  targetUrl: async ({}, use) => {
    await use(juiceShopUrl);
  },
});

export async function openJuiceShop(page: Page, targetUrl: string = juiceShopUrl): Promise<void> {
  const response = await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });

  if (!response?.ok()) {
    throw new Error(
      `OWASP Juice Shop is required at ${targetUrl}. Start it with: docker compose -f docker-compose.vuln-apps.yml up -d juice-shop`
    );
  }

  await expect(page).toHaveTitle(/OWASP Juice Shop/i);

  const optionalDismissals = [
    'button[aria-label="Close Welcome Banner"]',
    'button:has-text("Dismiss")',
    'a:has-text("Me want it")',
    'button:has-text("Accept")',
  ];

  for (const selector of optionalDismissals) {
    const button = page.locator(selector).first();
    if (await button.isVisible({ timeout: 500 }).catch(() => false)) {
      await button.click({ timeout: 2_000 }).catch(() => undefined);
    }
  }
}

test.beforeEach(async ({ page, targetUrl }) => {
  await openJuiceShop(page, targetUrl);
});
