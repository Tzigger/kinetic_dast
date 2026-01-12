import { Page, Locator } from '@playwright/test';

/**
 * Find all input elements on a page
 */
export async function findInputElements(page: Page): Promise<Locator[]> {
  const selectors = [
    'input:not([type="hidden"]):not([type="submit"]):not([type="button"])',
    'textarea',
    'select',
    '[contenteditable="true"]',
  ];

  const elements: Locator[] = [];
  for (const selector of selectors) {
    const locators = await page.locator(selector).all();
    elements.push(...locators);
  }

  return elements;
}

/**
 * Find all forms on a page
 */
export async function findForms(page: Page): Promise<Locator[]> {
  return await page.locator('form').all();
}

/**
 * Find all links on a page
 */
export async function findLinks(page: Page): Promise<Locator[]> {
  return await page.locator('a[href]').all();
}

/**
 * Check if element is visible
 */
export async function isElementVisible(element: Locator): Promise<boolean> {
  try {
    return await element.isVisible();
  } catch {
    return false;
  }
}

/**
 * Check if element is editable
 */
export async function isElementEditable(element: Locator): Promise<boolean> {
  try {
    return await element.isEditable();
  } catch {
    return false;
  }
}

/**
 * Get element attributes
 */
export async function getElementAttributes(element: Locator): Promise<Record<string, string>> {
  try {
    const attributes: Record<string, string> = {};

    // Get common attributes
    const attrNames = ['id', 'name', 'class', 'type', 'value', 'placeholder', 'required'];

    for (const attr of attrNames) {
      const value = await element.getAttribute(attr);
      if (value !== null) {
        attributes[attr] = value;
      }
    }

    return attributes;
  } catch {
    return {};
  }
}

/**
 * Get element selector (CSS)
 */
export async function getElementSelector(element: Locator): Promise<string> {
  try {
    // Get a unique selector for the element
    const id = await element.getAttribute('id');
    if (id) {
      return `#${id}`;
    }

    const name = await element.getAttribute('name');
    if (name) {
      return `[name="${name}"]`;
    }

    // Fallback to tag name
    const tagName = await element.evaluate((el) => el.tagName.toLowerCase());
    return tagName;
  } catch {
    return 'unknown';
  }
}

/**
 * Get element position
 */
export async function getElementPosition(
  element: Locator
): Promise<{ x: number; y: number; width: number; height: number } | null> {
  try {
    const box = await element.boundingBox();
    return box;
  } catch {
    return null;
  }
}

/**
 * Wait for element to be stable
 */
export async function waitForElementStable(element: Locator, timeout = 1000): Promise<void> {
  try {
    await element.waitFor({ state: 'attached', timeout });
  } catch {
    // Element might not be stable, continue anyway
  }
}

/**
 * Safe fill - fills an input with error handling
 */
export async function safeFill(element: Locator, value: string): Promise<boolean> {
  try {
    await element.clear();
    await element.fill(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Safe click - clicks an element with error handling
 */
export async function safeClick(element: Locator): Promise<boolean> {
  try {
    await element.click({ timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get page HTML
 */
export async function getPageHTML(page: Page): Promise<string> {
  return await page.content();
}

/**
 * Get page text content
 */
export async function getPageText(page: Page): Promise<string> {
  return (await page.textContent('body')) || '';
}

/**
 * Take screenshot
 */
export async function takeScreenshot(page: Page): Promise<string> {
  const screenshot = await page.screenshot();
  return screenshot.toString('base64');
}

/**
 * Check if page has error messages
 */
export async function hasErrorMessages(page: Page): Promise<boolean> {
  const errorSelectors = [
    '.error',
    '.alert-error',
    '.alert-danger',
    '[class*="error"]',
    '[role="alert"]',
  ];

  for (const selector of errorSelectors) {
    const count = await page.locator(selector).count();
    if (count > 0) {
      return true;
    }
  }

  return false;
}

/**
 * Get error messages from page
 */
export async function getErrorMessages(page: Page): Promise<string[]> {
  const errorSelectors = [
    '.error',
    '.alert-error',
    '.alert-danger',
    '[class*="error"]',
    '[role="alert"]',
  ];

  const messages: string[] = [];

  for (const selector of errorSelectors) {
    const elements = await page.locator(selector).all();
    for (const element of elements) {
      const text = await element.textContent();
      if (text) {
        messages.push(text.trim());
      }
    }
  }

  return messages;
}
