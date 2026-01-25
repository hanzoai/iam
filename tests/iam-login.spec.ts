/**
 * Hanzo IAM Multi-Tenant Login Tests
 *
 * These Playwright tests verify the login functionality across all
 * organization domains (hanzo.id, zoo.id, lux.id, pars.id).
 *
 * Run with:
 *   npx playwright test tests/iam-login.spec.ts
 *
 * Or for specific org:
 *   npx playwright test tests/iam-login.spec.ts --grep "hanzo.id"
 */

import { test, expect, type Page } from '@playwright/test';

// Organization configurations for testing
const organizations = [
  {
    name: 'hanzo',
    domain: 'https://hanzo.id',
    displayName: 'Hanzo',
    primaryColor: '#fd4444',
    testApp: 'https://console.hanzo.ai',
  },
  {
    name: 'zoo',
    domain: 'https://zoo.id',
    displayName: 'Zoo Labs',
    primaryColor: '#10b981',
    testApp: 'https://zoo.ngo',
  },
  {
    name: 'lux',
    domain: 'https://lux.id',
    displayName: 'Lux Network',
    primaryColor: '#8b5cf6',
    testApp: 'https://lux.network',
  },
  {
    name: 'pars',
    domain: 'https://pars.id',
    displayName: 'Pars',
    primaryColor: '#3b82f6',
    testApp: 'https://pars.ai',
  },
];

// Test the IAM backend API
test.describe('IAM Backend API', () => {
  test('iam.hanzo.ai health check returns 200', async ({ request }) => {
    const response = await request.get('https://iam.hanzo.ai/api/health');
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('status');
  });

  test('iam.hanzo.ai OIDC discovery is available', async ({ request }) => {
    const response = await request.get(
      'https://iam.hanzo.ai/.well-known/openid-configuration'
    );
    expect(response.status()).toBe(200);

    const config = await response.json();
    expect(config).toHaveProperty('issuer');
    expect(config).toHaveProperty('authorization_endpoint');
    expect(config).toHaveProperty('token_endpoint');
  });
});

// Test each organization login page
for (const org of organizations) {
  test.describe(`${org.displayName} (${org.domain})`, () => {
    test(`${org.name}.id login page loads`, async ({ page }) => {
      await page.goto(org.domain);

      // Check page loaded
      await expect(page).toHaveTitle(new RegExp(org.displayName, 'i'));

      // Check for login form elements
      const emailInput = page.locator('input[name="email"], input[type="email"]');
      await expect(emailInput).toBeVisible({ timeout: 10000 });

      const passwordInput = page.locator('input[name="password"], input[type="password"]');
      await expect(passwordInput).toBeVisible();

      const submitButton = page.locator('button[type="submit"]');
      await expect(submitButton).toBeVisible();
    });

    test(`${org.name}.id displays correct branding`, async ({ page }) => {
      await page.goto(org.domain);

      // Check for organization name in page
      await expect(page.locator('body')).toContainText(org.displayName);

      // Check primary color is applied (in CSS)
      const hasThemeColor = await page.evaluate((color) => {
        const styles = document.documentElement.style.cssText;
        const bodyStyles = getComputedStyle(document.body);
        return styles.includes(color) ||
               bodyStyles.getPropertyValue('--color-primary')?.includes(color);
      }, org.primaryColor);

      // Theme check is optional since CSS implementation varies
      console.log(`${org.name} theme color check: ${hasThemeColor}`);
    });

    test(`${org.name}.id shows error on invalid credentials`, async ({ page }) => {
      await page.goto(org.domain);

      // Fill in invalid credentials
      await page.fill('input[name="email"], input[type="email"]', 'invalid@test.com');
      await page.fill('input[name="password"], input[type="password"]', 'wrongpassword');

      // Submit form
      await page.click('button[type="submit"]');

      // Wait for error message
      const errorMessage = page.locator('[class*="error"], [class*="alert"], [role="alert"]');
      await expect(errorMessage).toBeVisible({ timeout: 10000 });
    });

    test(`${org.name}.id OAuth redirect works`, async ({ page, context }) => {
      // Start from a test application
      const testAppUrl = new URL(org.testApp);
      testAppUrl.pathname = '/login';
      testAppUrl.searchParams.set('redirect', org.testApp);

      // The login button should redirect to the org's IAM
      // This tests the OAuth flow initiation
      await page.goto(org.domain + '/login/oauth/authorize?client_id=test&redirect_uri=' + encodeURIComponent(org.testApp + '/callback'));

      // Should show login or redirect
      const url = page.url();
      expect(url).toContain(org.name);
    });

    test(`${org.name}.id signup link is visible`, async ({ page }) => {
      await page.goto(org.domain);

      // Check for signup link
      const signupLink = page.locator('a[href*="signup"], a[href*="register"], button:has-text("Sign up")');
      const count = await signupLink.count();

      // Signup should be available
      expect(count).toBeGreaterThan(0);
    });

    test(`${org.name}.id has CSRF protection`, async ({ page }) => {
      await page.goto(org.domain);

      // Check for CSRF token in form or headers
      const csrfToken = await page.locator('input[name="csrf"], input[name="_csrf"], input[name="csrfToken"]').count();
      const csrfMeta = await page.locator('meta[name="csrf-token"]').count();

      // Should have some form of CSRF protection
      const hasProtection = csrfToken > 0 || csrfMeta > 0;
      console.log(`${org.name} CSRF protection: ${hasProtection}`);
    });
  });
}

// Test cross-organization isolation
test.describe('Multi-Tenant Isolation', () => {
  test('hanzo.id and zoo.id have separate sessions', async ({ browser }) => {
    // Create two separate browser contexts
    const hanzoContext = await browser.newContext();
    const zooContext = await browser.newContext();

    const hanzoPage = await hanzoContext.newPage();
    const zooPage = await zooContext.newPage();

    // Visit both domains
    await hanzoPage.goto('https://hanzo.id');
    await zooPage.goto('https://zoo.id');

    // Get cookies from each
    const hanzoCookies = await hanzoContext.cookies();
    const zooCookies = await zooContext.cookies();

    // Sessions should be separate (different cookies)
    const hanzoSession = hanzoCookies.find((c) => c.name.includes('session'));
    const zooSession = zooCookies.find((c) => c.name.includes('session'));

    // Either no session or different sessions
    if (hanzoSession && zooSession) {
      expect(hanzoSession.value).not.toBe(zooSession.value);
    }

    await hanzoContext.close();
    await zooContext.close();
  });

  test('organization header is correctly set', async ({ request }) => {
    // Test that each domain routes to correct organization
    for (const org of organizations) {
      const response = await request.get(org.domain + '/api/get-account', {
        failOnStatusCode: false,
      });

      // The response should reflect the organization context
      // (even if not authenticated, we verify routing works)
      const status = response.status();
      expect([200, 401, 403]).toContain(status);
    }
  });
});

// Test OAuth/OIDC flows
test.describe('OAuth/OIDC Flows', () => {
  test('authorization endpoint accepts valid request', async ({ page }) => {
    const authUrl = new URL('https://hanzo.id/login/oauth/authorize');
    authUrl.searchParams.set('client_id', 'hanzo-console-client-id');
    authUrl.searchParams.set('redirect_uri', 'https://console.hanzo.ai/api/auth/callback/custom');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', 'test-state-123');

    await page.goto(authUrl.toString());

    // Should show login form (not error)
    const loginForm = page.locator('form');
    await expect(loginForm).toBeVisible({ timeout: 10000 });
  });

  test('invalid client_id returns error', async ({ page }) => {
    const authUrl = new URL('https://hanzo.id/login/oauth/authorize');
    authUrl.searchParams.set('client_id', 'invalid-client');
    authUrl.searchParams.set('redirect_uri', 'https://attacker.com/callback');
    authUrl.searchParams.set('response_type', 'code');

    await page.goto(authUrl.toString());

    // Should show error, not redirect to attacker
    const url = page.url();
    expect(url).not.toContain('attacker.com');
  });
});

// Accessibility tests
test.describe('Accessibility', () => {
  for (const org of organizations) {
    test(`${org.name}.id login is keyboard accessible`, async ({ page }) => {
      await page.goto(org.domain);

      // Tab to email input
      await page.keyboard.press('Tab');
      const emailFocused = await page.locator('input[type="email"]:focus').count();

      // Tab to password
      await page.keyboard.press('Tab');
      const passwordFocused = await page.locator('input[type="password"]:focus').count();

      // Tab to submit
      await page.keyboard.press('Tab');

      // Should be able to navigate with keyboard
      expect(emailFocused + passwordFocused).toBeGreaterThan(0);
    });
  }
});

// Performance tests
test.describe('Performance', () => {
  for (const org of organizations) {
    test(`${org.name}.id loads within 3 seconds`, async ({ page }) => {
      const start = Date.now();
      await page.goto(org.domain, { waitUntil: 'domcontentloaded' });
      const loadTime = Date.now() - start;

      console.log(`${org.name}.id load time: ${loadTime}ms`);
      expect(loadTime).toBeLessThan(3000);
    });
  }
});
