import { chromium } from 'playwright';

const VIEWPORT = { width: 1440, height: 900 };
const BASE = 'https://iam.next.example.internal';
const OUT = '/Users/z/work/hanzo/iam/screenshots';

const pages = [
  { url: `${BASE}/login`, name: '01-login', label: 'Login page' },
  { url: `${BASE}/signup`, name: '02-signup', label: 'Signup page' },
  { url: `${BASE}/forget`, name: '03-forgot-password', label: 'Forgot password page' },
  { url: `${BASE}/nonexistent-404`, name: '04-404-page', label: '404 page' },
  { url: `${BASE}/`, name: '05-home-dashboard', label: 'Home/dashboard page' },
];

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: VIEWPORT,
    colorScheme: 'dark',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  });

  for (const page of pages) {
    console.log(`\n--- ${page.label} ---`);
    console.log(`Navigating to: ${page.url}`);
    const p = await context.newPage();
    try {
      const response = await p.goto(page.url, { waitUntil: 'networkidle', timeout: 30000 });
      console.log(`Status: ${response?.status()}`);
      console.log(`Final URL: ${p.url()}`);

      // Wait for rendering
      await p.waitForTimeout(3000);

      // Get page dimensions
      const dims = await p.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        scrollHeight: document.documentElement.scrollHeight,
        clientWidth: document.documentElement.clientWidth,
        clientHeight: document.documentElement.clientHeight,
      }));
      console.log(`Page dimensions: ${JSON.stringify(dims)}`);

      // Full page screenshot
      await p.screenshot({ path: `${OUT}/${page.name}.png`, fullPage: true });
      console.log(`Saved full: ${OUT}/${page.name}.png`);

      // Viewport-only screenshot
      await p.screenshot({ path: `${OUT}/${page.name}-viewport.png`, fullPage: false });
      console.log(`Saved viewport: ${OUT}/${page.name}-viewport.png`);

      // Log interesting elements
      const bodyBg = await p.evaluate(() => {
        const body = document.body;
        const style = getComputedStyle(body);
        return { bg: style.backgroundColor, color: style.color };
      });
      console.log(`Body styles: ${JSON.stringify(bodyBg)}`);

      // Check for forms, inputs, buttons
      const elements = await p.evaluate(() => {
        const forms = document.querySelectorAll('form');
        const inputs = document.querySelectorAll('input');
        const buttons = document.querySelectorAll('button');
        const imgs = document.querySelectorAll('img');
        const antElements = document.querySelectorAll('[class*="ant-"]');
        const links = document.querySelectorAll('a');

        return {
          forms: forms.length,
          inputs: Array.from(inputs).map(i => ({ type: i.type, placeholder: i.placeholder, name: i.name })),
          buttons: Array.from(buttons).map(b => b.textContent?.trim().substring(0, 50)),
          images: Array.from(imgs).map(i => i.src.substring(0, 100)),
          antDesignElements: antElements.length,
          antDesignClasses: [...new Set(Array.from(antElements).map(e => {
            const classes = Array.from(e.classList).filter(c => c.startsWith('ant-'));
            return classes[0];
          }))].slice(0, 20),
          links: Array.from(links).map(l => ({ text: l.textContent?.trim().substring(0, 30), href: l.href.substring(0, 80) })),
        };
      });
      console.log(`Elements: ${JSON.stringify(elements, null, 2)}`);

      // Check for any upstream/Hanzo branding text leaks
      const brandingText = await p.evaluate(() => {
        const text = document.body.innerText;
        const matches: string[] = [];
        if (text.includes('Casdoor')) matches.push('Casdoor');
        if (text.includes('Hanzo')) matches.push('Hanzo');
        if (text.includes('partner')) matches.push('partner');
        if (text.includes('Liquidity')) matches.push('Liquidity');
        if (text.includes('Powered by')) {
          const idx = text.indexOf('Powered by');
          matches.push('Powered by: ' + text.substring(idx, idx + 40));
        }
        return { matches, fullText: text.substring(0, 500) };
      });
      console.log(`Branding: ${JSON.stringify(brandingText, null, 2)}`);

    } catch (e: any) {
      console.error(`Error on ${page.label}: ${e.message}`);
      try {
        await p.screenshot({ path: `${OUT}/${page.name}.png`, fullPage: true });
        console.log(`Saved (partial): ${OUT}/${page.name}.png`);
      } catch {}
    }
    await p.close();
  }

  await browser.close();
  console.log('\nDone!');
})();
