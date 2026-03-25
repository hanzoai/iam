import { chromium } from 'playwright';

const VIEWPORT = { width: 1440, height: 900 };
const BASE = 'https://iam.next.example.internal';
const OUT = '/Users/z/work/hanzo/iam/screenshots';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: VIEWPORT,
    colorScheme: 'dark',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  });

  // LOGIN PAGE - detailed investigation
  console.log('\n=== LOGIN PAGE DETAILED ===');
  const p = await context.newPage();

  const allRequests: string[] = [];
  const failedRequests: string[] = [];
  const consoleMessages: string[] = [];

  p.on('request', req => {
    allRequests.push(`${req.method()} ${req.url()}`);
  });
  p.on('requestfailed', req => {
    failedRequests.push(`FAIL: ${req.method()} ${req.url()} - ${req.failure()?.errorText}`);
  });
  p.on('response', resp => {
    if (resp.status() >= 400) {
      failedRequests.push(`${resp.status()}: ${resp.url()}`);
    }
  });
  p.on('console', msg => {
    consoleMessages.push(`[${msg.type()}] ${msg.text()}`);
  });

  await p.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded', timeout: 30000 });

  // Wait for network to settle
  await p.waitForTimeout(15000);

  console.log(`\nAll requests (${allRequests.length}):`);
  allRequests.forEach(r => console.log(`  ${r}`));

  console.log(`\nFailed/error requests (${failedRequests.length}):`);
  failedRequests.forEach(r => console.log(`  ${r}`));

  console.log(`\nConsole messages (${consoleMessages.length}):`);
  consoleMessages.forEach(r => console.log(`  ${r}`));

  // Check full HTML structure of the right panel area
  const htmlStructure = await p.evaluate(() => {
    const content = document.querySelector('.ant-layout-content');
    return content ? content.innerHTML.substring(0, 3000) : 'No .ant-layout-content found';
  });
  console.log(`\nLayout content HTML:\n${htmlStructure}`);

  // Check for any hidden elements or CSS hiding
  const spinnerInfo = await p.evaluate(() => {
    const spinner = document.querySelector('.ant-spin');
    if (!spinner) return 'No spinner found';
    const style = getComputedStyle(spinner);
    const parent = spinner.parentElement;
    const parentStyle = parent ? getComputedStyle(parent) : null;
    return {
      spinnerDisplay: style.display,
      spinnerVisibility: style.visibility,
      spinnerOpacity: style.opacity,
      spinnerPosition: style.position,
      spinnerRect: spinner.getBoundingClientRect(),
      parentTag: parent?.tagName,
      parentClass: parent?.className,
      parentDisplay: parentStyle?.display,
      parentRect: parent?.getBoundingClientRect(),
    };
  });
  console.log(`\nSpinner info: ${JSON.stringify(spinnerInfo, null, 2)}`);

  // Take screenshot with the spinner highlighted
  await p.screenshot({ path: `${OUT}/01-login.png`, fullPage: true });

  // Try to see if the form loads after removing the spinner
  // Also check if the page is trying to fetch an API that fails
  const apiCalls = allRequests.filter(r => r.includes('/api/') || r.includes('get-app-login'));
  console.log(`\nAPI calls: ${JSON.stringify(apiCalls, null, 2)}`);

  await p.close();

  // Now take proper screenshots of 404 page which DOES render
  console.log('\n=== 404 PAGE ===');
  const p404 = await context.newPage();
  await p404.goto(`${BASE}/nonexistent-404`, { waitUntil: 'networkidle', timeout: 30000 });
  await p404.waitForTimeout(3000);
  await p404.screenshot({ path: `${OUT}/04-404-page.png`, fullPage: true });

  // Check for the cartoon image and blue button
  const page404Info = await p404.evaluate(() => {
    const result = document.querySelector('.ant-result');
    const btn = document.querySelector('.ant-btn');
    const icon = document.querySelector('.ant-result-icon');
    const svgs = document.querySelectorAll('svg');

    return {
      resultClass: result?.className,
      btnClass: btn?.className,
      btnStyle: btn ? getComputedStyle(btn).backgroundColor : null,
      btnBorderColor: btn ? getComputedStyle(btn).borderColor : null,
      btnColor: btn ? getComputedStyle(btn).color : null,
      iconHTML: icon?.innerHTML?.substring(0, 200),
      svgCount: svgs.length,
      // Check for the question mark circle icon
      questionMark: document.querySelector('.anticon-question-circle') ? 'yes' : 'no',
      // Check all img tags
      images: Array.from(document.querySelectorAll('img')).map(i => ({
        src: i.src,
        width: i.width,
        height: i.height,
      })),
    };
  });
  console.log(`404 page info: ${JSON.stringify(page404Info, null, 2)}`);
  await p404.close();

  await browser.close();
  console.log('\nDone!');
})();
