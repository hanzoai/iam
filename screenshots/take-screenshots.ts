import { chromium } from '@playwright/test';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
  });

  const pages = [
    { url: 'https://iam.next./login', name: '01-login' },
    { url: 'https://iam.next./signup', name: '02-signup' },
    { url: 'https://iam.next./nonexistent-page-404', name: '03-404' },
    { url: 'https://iam.next./', name: '04-home' },
  ];

  for (const { url, name } of pages) {
    console.log(`Navigating to ${url}...`);
    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
      // Wait a bit for any animations/transitions to settle
      await page.waitForTimeout(2000);
      const path = `/Users/z/work/hanzo/iam/screenshots/${name}.png`;
      await page.screenshot({ path, fullPage: true });
      console.log(`  Saved: ${path}`);
    } catch (err) {
      console.error(`  Error on ${url}: ${err}`);
      // Still try to take a screenshot even if there was an error
      try {
        const path = `/Users/z/work/hanzo/iam/screenshots/${name}-error.png`;
        await page.screenshot({ path, fullPage: true });
        console.log(`  Saved error screenshot: ${path}`);
      } catch {}
    }
    await page.close();
  }

  await browser.close();
  console.log('Done!');
})();
