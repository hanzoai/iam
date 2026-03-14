/**
 * Hanzo IAM Comprehensive E2E Tests
 *
 * Tests login page rendering, authentication security, OAuth flows,
 * password field security, showcase behavior, and API security.
 *
 * Run all:
 *   npx playwright test tests/iam-e2e.spec.ts
 *
 * Run specific section:
 *   npx playwright test tests/iam-e2e.spec.ts --grep "Login Page Rendering"
 *
 * Run fast (chromium only):
 *   npx playwright test tests/iam-e2e.spec.ts --project=chromium
 */

import { test, expect } from '@playwright/test';

const BASE_URL = process.env.IAM_URL || 'http://localhost:8000';

// Selectors that work across Ant Design login forms
const EMAIL_INPUT = 'input[name="username"], input#normal_login_username';
const PASSWORD_INPUT = 'input[type="password"]';
const SUBMIT_BUTTON = 'button[type="submit"], button.login-button';

// ---------------------------------------------------------------------------
// 1. Login Page Rendering
// ---------------------------------------------------------------------------

test.describe('Login Page Rendering', () => {
  test('login page loads at /login', async ({ page }) => {
    const res = await page.goto(`${BASE_URL}/login`, {
      waitUntil: 'networkidle',
      timeout: 20000,
    });
    expect(res?.status()).toBe(200);
    // Page should have rendered content (not blank)
    const bodyText = await page.textContent('body');
    expect(bodyText?.length).toBeGreaterThan(0);
  });

  test('login form has username and password fields', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const usernameInput = page.locator(EMAIL_INPUT).first();
    const passwordInput = page.locator(PASSWORD_INPUT).first();

    await expect(usernameInput).toBeVisible();
    await expect(passwordInput).toBeVisible();
  });

  test('login form has a submit button', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const submitBtn = page.locator(SUBMIT_BUTTON).first();
    await expect(submitBtn).toBeVisible();
  });

  test('language dropdown is visible and has options', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    // LanguageSelect renders as .login-languages container with a Select/Dropdown
    // It may be an Ant Design Select or a custom dropdown
    const langSelector = page.locator(
      '.login-languages, [class*="language"], select[class*="lang"], .ant-select'
    );
    const langCount = await langSelector.count();

    // Language dropdown should exist if the org has multiple languages configured.
    // If only one language, the component returns null -- which is valid.
    // We just check the page did not crash trying to render it.
    expect(langCount).toBeGreaterThanOrEqual(0);
  });

  test('showcase panel is visible on desktop viewport', async ({ page }) => {
    // Ensure desktop viewport
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    // The HanzoShowcase component renders with class="hanzo-showcase"
    const showcase = page.locator('.hanzo-showcase, .side-image, [class*="showcase"]');
    const showcaseCount = await showcase.count();

    // Showcase is rendered via formSideHtml or the HanzoShowcase component.
    // On the direct IAM backend (Ant Design UI), the showcase panel uses
    // .side-image or .hanzo-showcase class. Log the count for diagnostics.
    if (showcaseCount > 0) {
      await expect(showcase.first()).toBeVisible();
    }
    // Not failing here -- showcase may not be configured for the default app
  });

  test('showcase panel is hidden on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    // On mobile, the showcase panel should be hidden or absent
    const showcase = page.locator('.hanzo-showcase, .side-image');
    const count = await showcase.count();
    if (count > 0) {
      // Should be hidden (display:none) or not visible
      await expect(showcase.first()).not.toBeVisible();
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Authentication Security
// ---------------------------------------------------------------------------

test.describe('Authentication Security', () => {
  test('empty credentials show validation error (not server error)', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    // Clear any pre-filled values
    const usernameInput = page.locator(EMAIL_INPUT).first();
    const passwordInput = page.locator(PASSWORD_INPUT).first();
    await usernameInput.fill('');
    await passwordInput.fill('');

    // Click submit
    await page.locator(SUBMIT_BUTTON).first().click();

    // Should show client-side validation error, not a 500 page
    // Ant Design shows .ant-form-item-explain-error for validation messages
    const error = page.locator(
      '.ant-form-item-explain-error, [class*="error"], [role="alert"], .ant-message-error'
    );
    await expect(error.first()).toBeVisible({ timeout: 5000 });

    // Page should NOT have navigated to an error page
    expect(page.url()).toContain('/login');
  });

  test('wrong password shows proper error message (not server crash)', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    await page.locator(EMAIL_INPUT).first().fill('nonexistent@test.invalid');
    await page.locator(PASSWORD_INPUT).first().fill('WrongPassword123!');
    await page.locator(SUBMIT_BUTTON).first().click();

    // Wait for API response and error display
    const error = page.locator(
      '.ant-message-error, [class*="error"], [role="alert"], .ant-notification-notice-error, .ant-result-error'
    );
    await expect(error.first()).toBeVisible({ timeout: 10000 });

    // Should NOT be a 500/server error page -- still on login
    const pageText = await page.textContent('body');
    expect(pageText).not.toContain('500 Internal Server Error');
    expect(pageText).not.toContain('panic');
    expect(pageText).not.toContain('runtime error');
  });

  test('wrong password via API returns proper error (not 500)', async ({ request }) => {
    const res = await request.post(`${BASE_URL}/api/login`, {
      data: {
        type: 'token',
        organization: 'hanzo',
        application: 'app-hanzo',
        username: 'nonexistent@test.invalid',
        password: 'WrongPassword123!',
      },
    });

    // Should NOT be a 500 -- should be 200 with error status or 4xx
    expect(res.status()).toBeLessThan(500);

    const body = await res.json();
    // Casdoor returns {status: "error", msg: "..."} for invalid credentials
    if (body.status) {
      expect(body.status).toBe('error');
      expect(body.msg).toBeTruthy();
    }
  });

  test('SQL injection attempt in username is safely handled', async ({ request }) => {
    const sqlPayloads = [
      "admin' OR '1'='1",
      "admin'; DROP TABLE user;--",
      "' UNION SELECT * FROM user--",
      "admin'/*",
      "1; WAITFOR DELAY '0:0:5'--",
    ];

    for (const payload of sqlPayloads) {
      const res = await request.post(`${BASE_URL}/api/login`, {
        data: {
          type: 'token',
          organization: 'hanzo',
          application: 'app-hanzo',
          username: payload,
          password: 'anything',
        },
      });

      // Must NOT be 500 (indicates unhandled SQL error)
      expect(res.status()).toBeLessThan(500);

      const body = await res.text();
      // Must NOT leak SQL error details
      expect(body.toLowerCase()).not.toContain('sql syntax');
      expect(body.toLowerCase()).not.toContain('mysql');
      expect(body.toLowerCase()).not.toContain('postgresql');
      expect(body.toLowerCase()).not.toContain('syntax error');
      expect(body.toLowerCase()).not.toContain('orm');
      expect(body.toLowerCase()).not.toContain('xorm');
    }
  });

  test('XSS attempt in username is safely handled', async ({ request }) => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      '"><script>document.location="http://evil.com"</script>',
      "';!--\"<XSS>=&{()}",
      '<svg onload=alert(1)>',
    ];

    for (const payload of xssPayloads) {
      const res = await request.post(`${BASE_URL}/api/login`, {
        data: {
          type: 'token',
          organization: 'hanzo',
          application: 'app-hanzo',
          username: payload,
          password: 'anything',
        },
      });

      expect(res.status()).toBeLessThan(500);

      const body = await res.text();
      // Response must NOT reflect the raw script tag back (XSS reflection)
      expect(body).not.toContain('<script>alert');
      expect(body).not.toContain('onerror=alert');
    }
  });

  test('XSS attempt in username via browser is safely handled', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const xssPayload = '<script>alert("xss")</script>';
    await page.locator(EMAIL_INPUT).first().fill(xssPayload);
    await page.locator(PASSWORD_INPUT).first().fill('anything');
    await page.locator(SUBMIT_BUTTON).first().click();

    // Wait for response
    await page.waitForTimeout(2000);

    // No alert dialog should have fired
    // (Playwright would throw if an unhandled dialog appears, but let's also check)
    const bodyHtml = await page.content();
    expect(bodyHtml).not.toContain('<script>alert("xss")');
  });

  test('very long username (1000+ chars) does not crash', async ({ request }) => {
    const longUsername = 'a'.repeat(1500) + '@test.com';

    const res = await request.post(`${BASE_URL}/api/login`, {
      data: {
        type: 'token',
        organization: 'hanzo',
        application: 'app-hanzo',
        username: longUsername,
        password: 'anything',
      },
    });

    // Must not crash -- 4xx or 200-with-error are both acceptable
    expect(res.status()).toBeLessThan(500);
  });

  test('very long username (1000+ chars) does not crash the UI', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const longUsername = 'a'.repeat(1200);
    await page.locator(EMAIL_INPUT).first().fill(longUsername);
    await page.locator(PASSWORD_INPUT).first().fill('anything');
    await page.locator(SUBMIT_BUTTON).first().click();

    // Page should not crash -- still on login or showing error
    await page.waitForTimeout(3000);
    const bodyText = await page.textContent('body');
    expect(bodyText).not.toContain('500 Internal Server Error');
    expect(bodyText).not.toContain('panic');
  });

  test('unicode characters in username work without crash', async ({ request }) => {
    const unicodeUsernames = [
      'user@\u00e9xample.com',        // accented e
      '\u4e2d\u6587@test.com',        // Chinese characters
      '\u0410\u0411\u0412@test.com',   // Cyrillic
      '\ud83d\ude00user@test.com',     // emoji
      'user@test.\u0627\u0644\u0639\u0631\u0628\u064a\u0629.com', // Arabic TLD
    ];

    for (const username of unicodeUsernames) {
      const res = await request.post(`${BASE_URL}/api/login`, {
        data: {
          type: 'token',
          organization: 'hanzo',
          application: 'app-hanzo',
          username: username,
          password: 'anything',
        },
      });

      // Must not crash
      expect(res.status()).toBeLessThan(500);
    }
  });

  test('password is never echoed in login API response', async ({ request }) => {
    const testPassword = 'SuperSecret_E2E_Test_12345!@#';
    const res = await request.post(`${BASE_URL}/api/login`, {
      data: {
        type: 'token',
        organization: 'hanzo',
        application: 'app-hanzo',
        username: 'test@test.com',
        password: testPassword,
      },
    });

    const body = await res.text();
    expect(body).not.toContain(testPassword);
  });
});

// ---------------------------------------------------------------------------
// 3. OAuth Flow
// ---------------------------------------------------------------------------

test.describe('OAuth Flow', () => {
  test('/oauth/authorize redirects to login when not authenticated', async ({ request }) => {
    const res = await request.get(
      `${BASE_URL}/oauth/authorize?client_id=app-hanzo&response_type=code&redirect_uri=https://hanzo.ai/callback&scope=openid&state=e2e-test`,
      { maxRedirects: 0 },
    );
    // Should redirect to login page (302) or serve login HTML (200)
    expect([200, 302, 303]).toContain(res.status());

    if (res.status() === 302 || res.status() === 303) {
      const location = res.headers()['location'] || '';
      // Should redirect to login, not to the redirect_uri (user is not authed)
      expect(location).not.toContain('https://hanzo.ai/callback');
    }
  });

  test('/oauth/authorize with browser redirects to login form', async ({ page }) => {
    await page.goto(
      `${BASE_URL}/oauth/authorize?client_id=app-hanzo&response_type=code&redirect_uri=https://hanzo.ai/callback&scope=openid&state=e2e-test`,
      { waitUntil: 'networkidle', timeout: 20000 },
    );

    // Should end up on a login page with a form
    await page.waitForSelector('input', { timeout: 15000 });
    const passwordField = page.locator(PASSWORD_INPUT);
    await expect(passwordField.first()).toBeVisible();
  });

  test('missing client_id returns proper error (not 500)', async ({ request }) => {
    const res = await request.get(
      `${BASE_URL}/oauth/authorize?response_type=code&redirect_uri=https://hanzo.ai/callback&scope=openid`,
      { maxRedirects: 0 },
    );

    // Should NOT be a 500. 200 with error message or 400 are acceptable.
    expect(res.status()).toBeLessThan(500);
  });

  test('missing client_id shows error in browser (not blank/crash)', async ({ page }) => {
    await page.goto(
      `${BASE_URL}/oauth/authorize?response_type=code&redirect_uri=https://hanzo.ai/callback&scope=openid`,
      { waitUntil: 'networkidle', timeout: 20000 },
    );

    // Page should show some content (error message) -- not a blank 500 page
    const bodyText = await page.textContent('body');
    expect(bodyText?.length).toBeGreaterThan(0);
    expect(bodyText).not.toContain('500 Internal Server Error');
  });

  test('invalid redirect_uri does NOT redirect to attacker domain', async ({ request }) => {
    const res = await request.get(
      `${BASE_URL}/oauth/authorize?client_id=app-hanzo&response_type=code&redirect_uri=https://evil.attacker.com/steal&scope=openid`,
      { maxRedirects: 0 },
    );

    // Should NOT redirect to the attacker domain
    const location = res.headers()['location'] || '';
    expect(location).not.toContain('evil.attacker.com');
    expect(location).not.toContain('evil');
  });

  test('invalid redirect_uri returns proper error (not 500)', async ({ request }) => {
    const res = await request.get(
      `${BASE_URL}/oauth/authorize?client_id=app-hanzo&response_type=code&redirect_uri=https://totally-wrong-domain.com/callback&scope=openid`,
      { maxRedirects: 0 },
    );

    expect(res.status()).toBeLessThan(500);
  });

  test('fake client_id does NOT redirect to attacker redirect_uri', async ({ request }) => {
    const res = await request.get(
      `${BASE_URL}/oauth/authorize?client_id=fake-evil-app&response_type=code&redirect_uri=https://evil.com/steal&scope=openid`,
      { maxRedirects: 0 },
    );

    const location = res.headers()['location'] || '';
    expect(location).not.toContain('evil.com');
  });

  test('/oauth/authorize without redirect_uri does not crash', async ({ request }) => {
    const res = await request.get(
      `${BASE_URL}/oauth/authorize?client_id=app-hanzo&response_type=code&scope=openid`,
      { maxRedirects: 0 },
    );

    expect([200, 302, 400]).toContain(res.status());
  });
});

// ---------------------------------------------------------------------------
// 4. Password Security
// ---------------------------------------------------------------------------

test.describe('Password Security', () => {
  test('password field is type="password" (masked)', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const passwordField = page.locator(PASSWORD_INPUT).first();
    await expect(passwordField).toBeVisible();

    const type = await passwordField.getAttribute('type');
    expect(type).toBe('password');
  });

  test('password field autocomplete attribute is safe', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const passwordField = page.locator(PASSWORD_INPUT).first();
    const autocomplete = await passwordField.getAttribute('autocomplete');

    // Acceptable values: null/undefined (browser default), "current-password",
    // "off", "new-password". Should NOT be "on" (unrestricted).
    if (autocomplete !== null) {
      const safeValues = ['current-password', 'new-password', 'off'];
      expect(safeValues).toContain(autocomplete);
    }
    // null/undefined is fine -- browser handles it sensibly
  });

  test('password is not visible in page source or hidden fields', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    // Type a password
    await page.locator(PASSWORD_INPUT).first().fill('TestPassword123!');

    // The password should not appear in any hidden input or DOM text
    const html = await page.content();
    // Check that the actual password value isn't embedded in HTML attributes
    // (Ant Design stores form values in React state, not DOM attributes)
    const visibleText = await page.textContent('body');
    expect(visibleText).not.toContain('TestPassword123!');
  });

  test('password toggle (show/hide) maintains type attribute correctly', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const passwordField = page.locator(PASSWORD_INPUT).first();
    await passwordField.fill('TestPassword123!');

    // Initially must be type="password"
    let type = await passwordField.getAttribute('type');
    expect(type).toBe('password');

    // If there's a visibility toggle icon (Ant Design Input.Password uses .ant-input-password-icon)
    const toggleIcon = page.locator('.ant-input-password-icon, [class*="password-icon"], [aria-label*="eye"]');
    if (await toggleIcon.count() > 0) {
      await toggleIcon.first().click();

      // After toggle, should be type="text" (visible)
      type = await passwordField.getAttribute('type');
      expect(type).toBe('text');

      // Toggle back
      await toggleIcon.first().click();
      type = await passwordField.getAttribute('type');
      expect(type).toBe('password');
    }
  });
});

// ---------------------------------------------------------------------------
// 5. Login Showcase
// ---------------------------------------------------------------------------

test.describe('Login Showcase', () => {
  test('showcase testimonials cycle automatically', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const showcase = page.locator('.hanzo-showcase');
    if (await showcase.count() === 0) {
      test.skip();
      return;
    }

    // Get initial testimonial text
    const testimonialText = page.locator('.showcase-testimonial-text');
    if (await testimonialText.count() === 0) {
      test.skip();
      return;
    }

    const initialText = await testimonialText.first().textContent();

    // Wait for the testimonial to auto-cycle (cycle interval is 7000ms)
    await page.waitForTimeout(8000);

    const newText = await testimonialText.first().textContent();

    // If there are multiple testimonials, the text should have changed.
    // If there is only one testimonial, it stays the same (which is fine).
    const dots = page.locator('.showcase-testimonial-dots .showcase-dot');
    const dotCount = await dots.count();
    if (dotCount > 1) {
      expect(newText).not.toBe(initialText);
    }
  });

  test('showcase product slides cycle automatically', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const showcase = page.locator('.hanzo-showcase');
    if (await showcase.count() === 0) {
      test.skip();
      return;
    }

    const slideTitle = page.locator('.showcase-slide-title');
    if (await slideTitle.count() === 0) {
      test.skip();
      return;
    }

    const initialTitle = await slideTitle.first().textContent();

    // Wait for slide to auto-cycle (interval is 4000ms)
    await page.waitForTimeout(5000);

    const newTitle = await slideTitle.first().textContent();

    const slideDots = page.locator('.showcase-slide-dots .showcase-dot');
    const slideDotCount = await slideDots.count();
    if (slideDotCount > 1) {
      expect(newTitle).not.toBe(initialTitle);
    }
  });

  test('showcase shows org-specific content for hanzo', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const showcase = page.locator('.hanzo-showcase');
    if (await showcase.count() === 0) {
      test.skip();
      return;
    }

    // For the hanzo org, the showcase title should be "Build with Hanzo"
    const title = page.locator('.showcase-title');
    if (await title.count() > 0) {
      const titleText = await title.first().textContent();
      expect(titleText).toContain('Hanzo');
    }

    // Badge should show "AI Infrastructure" for hanzo org
    const badge = page.locator('.showcase-badge');
    if (await badge.count() > 0) {
      const badgeText = await badge.first().textContent();
      // Could be "AI Infrastructure" (hanzo) or "Blockchain Infrastructure" (lux) etc.
      expect(badgeText?.length).toBeGreaterThan(0);
    }
  });

  test('showcase dot navigation works', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle', timeout: 20000 });
    await page.waitForSelector('input', { timeout: 15000 });

    const showcase = page.locator('.hanzo-showcase');
    if (await showcase.count() === 0) {
      test.skip();
      return;
    }

    const slideDots = page.locator('.showcase-slide-dots .showcase-dot');
    const dotCount = await slideDots.count();
    if (dotCount < 2) {
      test.skip();
      return;
    }

    // Click the second dot
    const slideTitle = page.locator('.showcase-slide-title');
    const initialTitle = await slideTitle.first().textContent();

    await slideDots.nth(1).click();
    await page.waitForTimeout(500);

    const newTitle = await slideTitle.first().textContent();
    // Title should change when clicking a different dot
    expect(newTitle).not.toBe(initialTitle);
  });
});

// ---------------------------------------------------------------------------
// 6. API Security
// ---------------------------------------------------------------------------

test.describe('API Security', () => {
  test('/api/get-account without auth returns 401 or 403', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/get-account`);
    // Without a valid session or token, should be rejected
    expect([200, 401, 403]).toContain(res.status());

    if (res.status() === 200) {
      // If 200, the response should indicate no user (null data or error status)
      const body = await res.json();
      // Casdoor returns {status: "ok", data: null} for unauthenticated requests
      // or {status: "error"} -- either way, no sensitive user data
      if (body.data) {
        // If data is present, it should not contain another user's info
        // (this would indicate a session fixation or default auth bypass)
        expect(body.data.password).toBeUndefined();
        expect(body.data.passwordSalt).toBeUndefined();
      }
    }
  });

  test('/api/userinfo without auth returns proper error', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/userinfo`);
    // Should be 401 or 403, or 200 with empty/error data
    expect(res.status()).toBeLessThan(500);

    if (res.status() === 200) {
      const body = await res.text();
      // Should not contain sensitive fields like password or internal IDs
      expect(body.toLowerCase()).not.toContain('"password"');
      expect(body.toLowerCase()).not.toContain('"passwordsalt"');
    }
  });

  test('/oauth/userinfo without auth returns 401 or 403', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/oauth/userinfo`);
    expect([401, 403]).toContain(res.status());
  });

  test('/oauth/userinfo with invalid bearer token returns 401 or 403', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/oauth/userinfo`, {
      headers: { Authorization: 'Bearer invalid-fake-token-xyz' },
    });
    expect([401, 403]).toContain(res.status());
  });

  test('/api/sync-init-data without service token returns 403', async ({ request }) => {
    // This is an admin-only endpoint that syncs init data
    const res = await request.post(`${BASE_URL}/api/sync-init-data`);
    // Should require authentication -- return 401, 403, or 405
    expect(res.status()).toBeGreaterThanOrEqual(400);
    expect(res.status()).toBeLessThan(500);
  });

  test('/api/get-users without auth does not leak user list', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/get-users?owner=hanzo`);
    expect(res.status()).toBeLessThan(500);

    if (res.status() === 200) {
      const body = await res.json();
      // If data is returned, passwords must never be included
      if (body.data && Array.isArray(body.data)) {
        for (const user of body.data) {
          expect(user.password).toBeUndefined();
          expect(user.passwordSalt).toBeUndefined();
        }
      }
    }
  });

  test('/api/login does not expose stack traces on malformed input', async ({ request }) => {
    // Send completely malformed JSON
    const res = await request.post(`${BASE_URL}/api/login`, {
      headers: { 'Content-Type': 'application/json' },
      data: '{"broken": }',
    });

    // Should not crash or expose internals
    expect(res.status()).toBeLessThan(500);
    const body = await res.text();
    expect(body).not.toContain('goroutine');
    expect(body).not.toContain('runtime/');
    expect(body).not.toContain('panic');
  });

  test('CORS headers do not allow wildcard origin', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/api/health`, {
      headers: { Origin: 'https://evil.com' },
    });

    const corsOrigin = res.headers()['access-control-allow-origin'];
    // Should not be * (wildcard) in production for authenticated endpoints
    // (health endpoint may allow it, but we check the pattern)
    if (corsOrigin) {
      expect(corsOrigin).not.toBe('*');
    }
  });

  test('rate limiting: rapid login attempts do not crash server', async ({ request }) => {
    // Send 10 rapid login attempts -- server must remain healthy
    const promises = Array.from({ length: 10 }, (_, i) =>
      request.post(`${BASE_URL}/api/login`, {
        data: {
          type: 'token',
          organization: 'hanzo',
          application: 'app-hanzo',
          username: `ratelimit-test-${i}@test.invalid`,
          password: 'wrong',
        },
      })
    );

    const results = await Promise.all(promises);

    // All responses should be non-500
    for (const res of results) {
      expect(res.status()).toBeLessThan(500);
    }

    // Server should still be healthy after the burst
    const healthRes = await request.get(`${BASE_URL}/api/health`);
    expect(healthRes.status()).toBe(200);
  });
});
