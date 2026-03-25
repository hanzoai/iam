import { chromium } from 'playwright';

const VIEWPORT = { width: 1440, height: 900 };
const BASE = 'https://iam.next.';
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
    const p = await context.newPage();

    // Capture console errors
    const consoleErrors: string[] = [];
    p.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Capture network failures
    const networkErrors: string[] = [];
    p.on('requestfailed', req => {
      networkErrors.push(`${req.method()} ${req.url()} - ${req.failure()?.errorText}`);
    });

    try {
      const response = await p.goto(page.url, { waitUntil: 'networkidle', timeout: 30000 });
      console.log(`Status: ${response?.status()}, URL: ${p.url()}`);

      // Wait longer - maybe spinning form needs time
      await p.waitForTimeout(8000);

      // Check if spinner is still showing
      const hasSpinner = await p.evaluate(() => {
        const spinners = document.querySelectorAll('.ant-spin, .ant-spin-spinning');
        return spinners.length;
      });
      console.log(`Active spinners: ${hasSpinner}`);

      // Check for forms after long wait
      const formCheck = await p.evaluate(() => {
        const forms = document.querySelectorAll('form');
        const inputs = document.querySelectorAll('input');
        return {
          forms: forms.length,
          inputs: Array.from(inputs).map(i => ({ type: i.type, name: i.name, placeholder: i.placeholder })),
          allText: document.body.innerText.substring(0, 800),
        };
      });
      console.log(`Forms: ${formCheck.forms}, Inputs: ${JSON.stringify(formCheck.inputs)}`);
      console.log(`Page text:\n${formCheck.allText}`);

      if (consoleErrors.length > 0) {
        console.log(`Console errors: ${JSON.stringify(consoleErrors.slice(0, 5))}`);
      }
      if (networkErrors.length > 0) {
        console.log(`Network errors: ${JSON.stringify(networkErrors.slice(0, 5))}`);
      }

      // Screenshot
      await p.screenshot({ path: `${OUT}/${page.name}.png`, fullPage: true });
      console.log(`Saved: ${OUT}/${page.name}.png`);

      // Also try to get the right side panel - clip the right half
      await p.screenshot({
        path: `${OUT}/${page.name}-right.png`,
        clip: { x: 720, y: 0, width: 720, height: 900 }
      });
      console.log(`Saved right panel: ${OUT}/${page.name}-right.png`);

      // And left half
      await p.screenshot({
        path: `${OUT}/${page.name}-left.png`,
        clip: { x: 0, y: 0, width: 720, height: 900 }
      });
      console.log(`Saved left panel: ${OUT}/${page.name}-left.png`);

    } catch (e: any) {
      console.error(`Error: ${e.message}`);
      try {
        await p.screenshot({ path: `${OUT}/${page.name}.png` });
      } catch {}
    }
    await p.close();
  }

  await browser.close();
  console.log('\nDone!');
})();
