import { chromium } from 'playwright';

const VIEWPORT = { width: 1440, height: 900 };
const BASE = 'https://iam.next.';
const OUT = '/Users/z/work/hanzo/iam/screenshots';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: VIEWPORT,
    colorScheme: 'dark',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  });

  // LOGIN PAGE - detailed investigation
  console.log('\n=== LOGIN PAGE ===');
  const p = await context.newPage();

  const failedReqs: string[] = [];
  const apiCalls: string[] = [];
  const consoleErrs: string[] = [];

  p.on('response', resp => {
    const url = resp.url();
    if (url.includes('/v1/iam/') || url.includes('get-app')) {
      apiCalls.push(`${resp.status()} ${resp.url()}`);
    }
    if (resp.status() >= 400) {
      failedReqs.push(`${resp.status()}: ${url}`);
    }
  });
  p.on('console', msg => {
    if (msg.type() === 'error' || msg.type() === 'warning') {
      consoleErrs.push(`[${msg.type()}] ${msg.text().substring(0, 200)}`);
    }
  });

  try {
    await p.goto(`${BASE}/login`, { waitUntil: 'commit', timeout: 60000 });
    // Wait for page to load
    await p.waitForTimeout(20000);
  } catch (e: any) {
    console.log(`Navigation issue: ${e.message}`);
    await p.waitForTimeout(10000);
  }

  console.log(`Current URL: ${p.url()}`);

  console.log(`\nAPI calls: ${JSON.stringify(apiCalls, null, 2)}`);
  console.log(`Failed requests: ${JSON.stringify(failedReqs.slice(0, 10), null, 2)}`);
  console.log(`Console errors: ${JSON.stringify(consoleErrs.slice(0, 10), null, 2)}`);

  // Get HTML structure
  const html = await p.evaluate(() => {
    const content = document.querySelector('.ant-layout-content');
    return {
      contentHTML: content?.innerHTML?.substring(0, 4000) || 'none',
      hasForm: !!document.querySelector('form'),
      inputCount: document.querySelectorAll('input').length,
      spinnerCount: document.querySelectorAll('.ant-spin, .ant-spin-spinning').length,
      bodyClasses: document.body.className,
      title: document.title,
    };
  });
  console.log(`Page state: ${JSON.stringify(html, null, 2)}`);

  await p.screenshot({ path: `${OUT}/01-login.png`, fullPage: true });
  console.log('Saved login screenshot');

  await p.close();

  // SIGNUP
  console.log('\n=== SIGNUP PAGE ===');
  const p2 = await context.newPage();
  try {
    await p2.goto(`${BASE}/signup`, { waitUntil: 'commit', timeout: 60000 });
    await p2.waitForTimeout(20000);
  } catch (e: any) {
    console.log(`Navigation issue: ${e.message}`);
    await p2.waitForTimeout(10000);
  }
  console.log(`Current URL: ${p2.url()}`);
  await p2.screenshot({ path: `${OUT}/02-signup.png`, fullPage: true });
  const signupState = await p2.evaluate(() => ({
    hasForm: !!document.querySelector('form'),
    inputCount: document.querySelectorAll('input').length,
    title: document.title,
    bodyText: document.body.innerText.substring(0, 500),
  }));
  console.log(`Signup state: ${JSON.stringify(signupState, null, 2)}`);
  await p2.close();

  // FORGET
  console.log('\n=== FORGOT PASSWORD PAGE ===');
  const p3 = await context.newPage();
  try {
    await p3.goto(`${BASE}/forget`, { waitUntil: 'commit', timeout: 60000 });
    await p3.waitForTimeout(20000);
  } catch (e: any) {
    console.log(`Navigation issue: ${e.message}`);
    await p3.waitForTimeout(10000);
  }
  console.log(`Current URL: ${p3.url()}`);
  await p3.screenshot({ path: `${OUT}/03-forgot-password.png`, fullPage: true });
  const forgetState = await p3.evaluate(() => ({
    hasForm: !!document.querySelector('form'),
    inputCount: document.querySelectorAll('input').length,
    title: document.title,
    bodyText: document.body.innerText.substring(0, 500),
  }));
  console.log(`Forget state: ${JSON.stringify(forgetState, null, 2)}`);
  await p3.close();

  // 404
  console.log('\n=== 404 PAGE ===');
  const p4 = await context.newPage();
  try {
    await p4.goto(`${BASE}/nonexistent-404`, { waitUntil: 'commit', timeout: 60000 });
    await p4.waitForTimeout(10000);
  } catch (e: any) {
    console.log(`Navigation issue: ${e.message}`);
    await p4.waitForTimeout(10000);
  }
  console.log(`Current URL: ${p4.url()}`);
  await p4.screenshot({ path: `${OUT}/04-404-page.png`, fullPage: true });

  const page404 = await p4.evaluate(() => {
    const btn = document.querySelector('.ant-btn');
    const result = document.querySelector('.ant-result');
    return {
      btnBg: btn ? getComputedStyle(btn).backgroundColor : null,
      btnColor: btn ? getComputedStyle(btn).color : null,
      btnBorder: btn ? getComputedStyle(btn).borderColor : null,
      resultStatus: result?.className,
      bodyText: document.body.innerText.substring(0, 300),
      // Check all colored elements
      blueElements: Array.from(document.querySelectorAll('*')).filter(el => {
        const color = getComputedStyle(el).color;
        const bg = getComputedStyle(el).backgroundColor;
        return color.includes('24, 144, 255') || bg.includes('24, 144, 255') ||
               color.includes('1677ff') || bg.includes('1677ff') ||
               color.includes('22, 119, 255') || bg.includes('22, 119, 255');
      }).map(el => ({
        tag: el.tagName,
        class: el.className.toString().substring(0, 60),
        text: el.textContent?.substring(0, 30),
      })).slice(0, 10),
      // Check for cartoon/illustration SVGs or images
      svgs: document.querySelectorAll('svg').length,
      imgs: Array.from(document.querySelectorAll('img')).map(i => i.src),
    };
  });
  console.log(`404 info: ${JSON.stringify(page404, null, 2)}`);
  await p4.close();

  // HOME (redirects to login)
  console.log('\n=== HOME/DASHBOARD ===');
  const p5 = await context.newPage();
  try {
    await p5.goto(`${BASE}/`, { waitUntil: 'commit', timeout: 60000 });
    await p5.waitForTimeout(15000);
  } catch (e: any) {
    console.log(`Navigation issue: ${e.message}`);
    await p5.waitForTimeout(10000);
  }
  console.log(`Current URL: ${p5.url()}`);
  await p5.screenshot({ path: `${OUT}/05-home-dashboard.png`, fullPage: true });
  await p5.close();

  await browser.close();
  console.log('\nDone!');
})();
