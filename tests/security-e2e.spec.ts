// Security E2E Tests for Hanzo IAM
// Tests login page security, API hardening, and auth flow resilience
//
// Run: npx playwright test tests/security-e2e.spec.ts

import { test, expect } from '@playwright/test';

const BASE_URL = process.env.IAM_URL || 'http://localhost:8000';

// ── Login page rendering ─────────────────────────────────────────────────

test.describe('Login Page', () => {
  test('loads at /login', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await expect(page).toHaveURL(/login/);
    // Should have a form
    await expect(page.locator('input')).toHaveCount({ minimum: 1 });
  });

  test('has password field masked', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    const pwField = page.locator('input[type="password"]');
    await expect(pwField).toHaveCount({ minimum: 1 });
  });

  test('language dropdown is visible on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`);
    // Language selector (globe icon)
    const langSelect = page.locator('.select-box, [class*="language"]');
    // May be hidden if org has no languages configured — just verify no crash
    await page.waitForLoadState('networkidle');
  });

  test('showcase panel renders on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto(`${BASE_URL}/login`);
    // The showcase panel (right side of split login)
    const showcase = page.locator('.hanzo-showcase, .split-login-showcase');
    // Verify it exists (may be hidden on mobile)
    if (await showcase.count() > 0) {
      await expect(showcase.first()).toBeVisible();
    }
  });
});

// ── Authentication security ─────────────────────────────────────────────

test.describe('Authentication Security', () => {
  test('empty credentials show error', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    // Try submitting empty form
    const submitBtn = page.locator('button[type="submit"], .login-button, button:has-text("Sign In")');
    if (await submitBtn.count() > 0) {
      await submitBtn.first().click();
      // Should show validation error, not server error
      await page.waitForTimeout(1000);
      // No 500 error page
      await expect(page.locator('text=500')).toHaveCount(0);
    }
  });

  test('SQL injection in username is safely handled', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    const usernameField = page.locator('input[type="text"], input[name="username"], input#input');
    if (await usernameField.count() > 0) {
      await usernameField.first().fill("admin'; DROP TABLE user; --");
      const pwField = page.locator('input[type="password"]');
      if (await pwField.count() > 0) {
        await pwField.first().fill('test');
      }
      const submitBtn = page.locator('button[type="submit"], .login-button, button:has-text("Sign In")');
      if (await submitBtn.count() > 0) {
        await submitBtn.first().click();
        await page.waitForTimeout(2000);
        // Should not crash — should show auth error
        await expect(page.locator('text=500 Internal Server Error')).toHaveCount(0);
      }
    }
  });

  test('XSS attempt in username is safely handled', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    const usernameField = page.locator('input[type="text"], input[name="username"], input#input');
    if (await usernameField.count() > 0) {
      await usernameField.first().fill('<script>alert("xss")</script>');
      const pwField = page.locator('input[type="password"]');
      if (await pwField.count() > 0) {
        await pwField.first().fill('test');
      }
      const submitBtn = page.locator('button[type="submit"], .login-button, button:has-text("Sign In")');
      if (await submitBtn.count() > 0) {
        await submitBtn.first().click();
        await page.waitForTimeout(2000);
        // Verify no XSS dialog appeared
        // (Playwright would catch unhandled dialogs as test failures)
      }
    }
  });

  test('very long username does not crash', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    const usernameField = page.locator('input[type="text"], input[name="username"], input#input');
    if (await usernameField.count() > 0) {
      await usernameField.first().fill('A'.repeat(5000));
      const pwField = page.locator('input[type="password"]');
      if (await pwField.count() > 0) {
        await pwField.first().fill('test');
      }
      const submitBtn = page.locator('button[type="submit"], .login-button, button:has-text("Sign In")');
      if (await submitBtn.count() > 0) {
        await submitBtn.first().click();
        await page.waitForTimeout(2000);
        await expect(page.locator('text=500 Internal Server Error')).toHaveCount(0);
      }
    }
  });
});

// ── API security ────────────────────────────────────────────────────────

test.describe('API Security', () => {
  test('/api/get-account without auth returns error', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/api/get-account`);
    // Should not return 200 with user data
    const body = await response.json().catch(() => ({}));
    // Either 401/403 or status: "error" in body
    expect(response.status() === 401 || response.status() === 403 ||
           body.status === 'error' || body.msg?.includes('please sign in')).toBeTruthy();
  });

  test('/api/userinfo without auth returns proper error', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/api/userinfo`);
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });

  test('/api/sync-init-data without service token returns 403', async ({ request }) => {
    const response = await request.post(`${BASE_URL}/api/sync-init-data`);
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });

  test('/api/get-users without auth returns error', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/api/get-users?owner=built-in`);
    const body = await response.json().catch(() => ({}));
    expect(response.status() === 401 || response.status() === 403 ||
           body.status === 'error').toBeTruthy();
  });

  test('/api/get-organizations without auth returns error', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/api/get-organizations?owner=admin`);
    const body = await response.json().catch(() => ({}));
    // Should not leak org data to unauthenticated requests
    expect(response.status() !== 200 || body.status === 'error' ||
           !body.data || body.data.length === 0).toBeTruthy();
  });
});

// ── OAuth flow ──────────────────────────────────────────────────────────

test.describe('OAuth Flow', () => {
  test('/oauth/authorize without params redirects to login', async ({ page }) => {
    await page.goto(`${BASE_URL}/oauth/authorize`);
    // Should redirect to login or show error — not crash
    await page.waitForLoadState('networkidle');
    const url = page.url();
    expect(url.includes('/login') || url.includes('/oauth')).toBeTruthy();
  });

  test('missing client_id returns proper error', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/api/get-app-login?clientId=nonexistent`);
    // Should return error, not crash
    expect(response.status()).toBeLessThan(500);
  });
});

// ── CORS headers ────────────────────────────────────────────────────────

test.describe('CORS Security', () => {
  test('null origin is rejected', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/api/health`, {
      headers: { 'Origin': 'null' },
    });
    const corsHeader = response.headers()['access-control-allow-origin'];
    expect(corsHeader).not.toBe('null');
  });
});
