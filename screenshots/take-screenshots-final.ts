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

  // ===== LOGIN =====
  console.log('=== LOGIN ===');
  const p1 = await context.newPage();

  // Track API responses
  const apiResponses: Record<string, any> = {};
  p1.on('response', async resp => {
    const url = resp.url();
    if (url.includes('/v1/iam/')) {
      try {
        const json = await resp.json();
        const key = url.replace(BASE, '');
        apiResponses[key] = { status: resp.status(), data: JSON.stringify(json).substring(0, 500) };
      } catch {}
    }
  });

  await p1.goto(`${BASE}/login`, { waitUntil: 'load', timeout: 60000 });
  await p1.waitForTimeout(10000);

  console.log('API responses:', JSON.stringify(apiResponses, null, 2));
  console.log('Title:', await p1.title());

  // Check what the spinner container looks like and if there's content behind it
  const loginDebug = await p1.evaluate(() => {
    const formContainer = document.querySelector('.split-login-form');
    if (!formContainer) return { error: 'No form container' };

    const children = formContainer.children;
    const childInfo = Array.from(children).map(c => ({
      tag: c.tagName,
      class: c.className.toString().substring(0, 100),
      display: getComputedStyle(c).display,
      visibility: getComputedStyle(c).visibility,
      childCount: c.children.length,
      text: c.textContent?.substring(0, 100),
    }));

    return {
      containerStyle: {
        bg: getComputedStyle(formContainer).backgroundColor,
        bgImage: getComputedStyle(formContainer).backgroundImage?.substring(0, 100),
        width: getComputedStyle(formContainer).width,
        display: getComputedStyle(formContainer).display,
      },
      children: childInfo,
      fullHTML: formContainer.innerHTML.substring(0, 2000),
    };
  });
  console.log('Login form debug:', JSON.stringify(loginDebug, null, 2));

  await p1.screenshot({ path: `${OUT}/01-login.png`, fullPage: true });
  await p1.close();

  // ===== SIGNUP =====
  console.log('\n=== SIGNUP ===');
  const p2 = await context.newPage();
  await p2.goto(`${BASE}/signup`, { waitUntil: 'load', timeout: 60000 });
  await p2.waitForTimeout(10000);
  console.log('Title:', await p2.title());
  await p2.screenshot({ path: `${OUT}/02-signup.png`, fullPage: true });
  await p2.close();

  // ===== FORGET =====
  console.log('\n=== FORGOT PASSWORD ===');
  const p3 = await context.newPage();
  await p3.goto(`${BASE}/forget`, { waitUntil: 'load', timeout: 60000 });
  await p3.waitForTimeout(10000);
  console.log('Title:', await p3.title());
  await p3.screenshot({ path: `${OUT}/03-forgot-password.png`, fullPage: true });
  await p3.close();

  // ===== 404 =====
  console.log('\n=== 404 ===');
  const p4 = await context.newPage();
  await p4.goto(`${BASE}/nonexistent-404`, { waitUntil: 'load', timeout: 60000 });
  await p4.waitForTimeout(10000);
  console.log('Title:', await p4.title());

  // Get detailed 404 info
  const info404 = await p4.evaluate(() => {
    const body = document.body;
    const headerBg = getComputedStyle(document.querySelector('.ant-layout-header') || body).backgroundColor;

    // Find all ant-design blue elements
    const allElements = document.querySelectorAll('*');
    const blueEls: any[] = [];
    allElements.forEach(el => {
      const cs = getComputedStyle(el);
      if (cs.backgroundColor.match(/rgb\(22,\s*119,\s*255\)|rgb\(24,\s*144,\s*255\)|#1677ff|#1890ff/)) {
        blueEls.push({
          tag: el.tagName,
          class: el.className.toString().substring(0, 60),
          bg: cs.backgroundColor,
        });
      }
      if (cs.color.match(/rgb\(22,\s*119,\s*255\)|rgb\(24,\s*144,\s*255\)|#1677ff|#1890ff/)) {
        blueEls.push({
          tag: el.tagName,
          class: el.className.toString().substring(0, 60),
          color: cs.color,
        });
      }
    });

    // Check the "Back Home" button
    const btn = document.querySelector('.ant-btn');
    const btnStyles = btn ? {
      bg: getComputedStyle(btn).backgroundColor,
      color: getComputedStyle(btn).color,
      border: getComputedStyle(btn).border,
      borderRadius: getComputedStyle(btn).borderRadius,
    } : null;

    // Check for cartoon SVG - the result icon area
    const resultIcon = document.querySelector('.ant-result-icon');
    const resultIconInfo = resultIcon ? {
      width: resultIcon.clientWidth,
      height: resultIcon.clientHeight,
      childCount: resultIcon.children.length,
      innerHTML: resultIcon.innerHTML.substring(0, 300),
    } : null;

    // Check the globe/language icon in header
    const headerEl = document.querySelector('.ant-layout-header');
    const dropdownTrigger = document.querySelector('.ant-dropdown-trigger');

    return {
      headerBg,
      blueElements: blueEls,
      btnStyles,
      resultIconInfo,
      hasGlobeIcon: !!dropdownTrigger,
      title: document.title,
      footerText: document.querySelector('.ant-layout-footer')?.textContent,
    };
  });
  console.log('404 details:', JSON.stringify(info404, null, 2));

  await p4.screenshot({ path: `${OUT}/04-404-page.png`, fullPage: true });
  await p4.close();

  // ===== HOME -> LOGIN redirect =====
  console.log('\n=== HOME (redirects to login) ===');
  const p5 = await context.newPage();
  await p5.goto(`${BASE}/`, { waitUntil: 'load', timeout: 60000 });
  await p5.waitForTimeout(10000);
  console.log('Title:', await p5.title());
  console.log('URL:', p5.url());
  await p5.screenshot({ path: `${OUT}/05-home-dashboard.png`, fullPage: true });
  await p5.close();

  await browser.close();
  console.log('\nDone! All screenshots saved.');
})();
