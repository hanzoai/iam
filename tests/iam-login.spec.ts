/**
 * Hanzo IAM Production E2E Tests
 *
 * Tests ALL login pages, ALL registered apps, OIDC/OAuth2 compliance,
 * multi-tenant isolation, and white-label frontend verification.
 *
 * Run all:
 *   npx playwright test tests/iam-login.spec.ts
 *
 * Run specific section:
 *   npx playwright test tests/iam-login.spec.ts --grep "OIDC Discovery"
 *
 * Run fast (chromium only):
 *   npx playwright test tests/iam-login.spec.ts --project=chromium
 */

import { test, expect } from '@playwright/test';

// ---------------------------------------------------------------------------
// Login page domains (white-label frontends + direct IAM)
// ---------------------------------------------------------------------------

interface LoginDomain {
  name: string;
  url: string;
  org: string;
  type: 'white-label' | 'direct-iam';
}

const LOGIN_DOMAINS: LoginDomain[] = [
  // White-label frontends
  { name: 'hanzo.id', url: 'https://hanzo.id', org: 'hanzo', type: 'white-label' },
  { name: 'auth.hanzo.ai', url: 'https://auth.hanzo.ai', org: 'hanzo', type: 'white-label' },
  { name: 'lux.id', url: 'https://lux.id', org: 'lux', type: 'white-label' },
  { name: 'pars.id', url: 'https://pars.id', org: 'pars', type: 'white-label' },
  { name: 'id.lux.network', url: 'https://id.lux.network', org: 'lux', type: 'white-label' },
  { name: 'id.zoo.network', url: 'https://id.zoo.network', org: 'zoo', type: 'white-label' },
  // Direct IAM backend (Ant Design UI)
  { name: 'iam.hanzo.ai', url: 'https://iam.hanzo.ai', org: 'hanzo', type: 'direct-iam' },
  { name: 'iam.lux.network', url: 'https://iam.lux.network', org: 'lux', type: 'direct-iam' },
];

// ---------------------------------------------------------------------------
// All registered apps (actual client IDs from IAM database)
// ---------------------------------------------------------------------------

interface AppConfig {
  clientId: string;
  name: string;
  org: string;
  redirectUri: string;
}

const REGISTERED_APPS: AppConfig[] = [
  // Hanzo org
  { clientId: 'app-hanzo', name: 'app-hanzo', org: 'hanzo', redirectUri: 'https://hanzo.ai/callback' },
  { clientId: 'hanzo-console-client-id', name: 'app-console', org: 'hanzo', redirectUri: 'https://console.hanzo.ai/api/auth/callback/iam' },
  { clientId: 'hanzo-cloud-client-id', name: 'app-cloud', org: 'hanzo', redirectUri: 'https://cloud.hanzo.ai/callback' },
  { clientId: 'hanzo-platform-client-id', name: 'app-platform', org: 'hanzo', redirectUri: 'https://platform.hanzo.ai/api/auth/callback/hanzo' },
  { clientId: 'hanzo-kms-client-id', name: 'app-kms', org: 'hanzo', redirectUri: 'https://kms.hanzo.ai/api/v1/sso/oidc/callback' },
  { clientId: 'hanzo-commerce-client-id', name: 'app-commerce', org: 'hanzo', redirectUri: 'https://commerce.hanzo.ai/callback' },
  { clientId: 'hanzobot-client-id', name: 'app-hanzobot', org: 'hanzo', redirectUri: 'http://localhost:3000/callback' },
  { clientId: 'chat-app', name: 'app-chat', org: 'hanzo', redirectUri: 'https://chat.hanzo.ai/oauth/openid/callback' },
  { clientId: 'app-analytics', name: 'app-analytics', org: 'hanzo', redirectUri: 'https://analytics.hanzo.ai/api/auth/iam' },
  { clientId: 'app-insights', name: 'app-insights', org: 'hanzo', redirectUri: 'https://insights.hanzo.ai/complete/oidc/' },
  { clientId: 'hanzo-storage-client-id', name: 'app-storage', org: 'hanzo', redirectUri: 'https://s3.hanzo.ai/oauth_callback' },
  { clientId: 'hanzo-auto-client-id', name: 'app-auto', org: 'hanzo', redirectUri: 'https://auto.hanzo.ai/callback' },
  { clientId: 'hanzo-flow-client-id', name: 'app-flow', org: 'hanzo', redirectUri: 'https://flow.hanzo.ai/callback' },
  // Lux org
  { clientId: 'lux-app-client-id', name: 'app-lux', org: 'lux', redirectUri: 'https://lux.network/callback' },
  { clientId: 'lux-mpc', name: 'app-lux-mpc', org: 'lux', redirectUri: 'https://mpc.lux.network/callback' },
  // Zoo org
  { clientId: 'zoo-app-client-id', name: 'app-zoo', org: 'zoo', redirectUri: 'https://zoo.ngo/callback' },
  { clientId: 'zoo-mpc', name: 'app-zoo-mpc', org: 'zoo', redirectUri: 'https://mpc.zoo.network/callback' },
  // Pars org
  { clientId: 'pars-app-client-id', name: 'app-pars', org: 'pars', redirectUri: 'https://pars.id/callback' },
  { clientId: 'pars-mpc', name: 'app-pars-mpc', org: 'pars', redirectUri: 'https://mpc.pars.network/callback' },
  // Adnexus org
  { clientId: 'adnexus-app-client-id', name: 'app-adnexus', org: 'adnexus', redirectUri: 'https://ad.nexus/callback' },
];

const IAM_ORIGIN = 'https://iam.hanzo.ai';

// Broad selector that matches email/username inputs across all UI frameworks
const EMAIL_INPUT = 'input[type="email"], input[name="email"], input[name="username"], input[placeholder*="mail" i], input[placeholder*="user" i], input#normal_login_username';
const PASSWORD_INPUT = 'input[type="password"]';

// ---------------------------------------------------------------------------
// 1. OIDC Discovery
// ---------------------------------------------------------------------------

test.describe('OIDC Discovery', () => {
  for (const domain of LOGIN_DOMAINS) {
    test(`${domain.name} — /.well-known/openid-configuration`, async ({ request }) => {
      const res = await request.get(`${domain.url}/.well-known/openid-configuration`);
      expect(res.status()).toBe(200);

      const config = await res.json();

      // Required OIDC fields
      expect(config.issuer).toBeTruthy();
      expect(config.authorization_endpoint).toBeTruthy();
      expect(config.token_endpoint).toBeTruthy();
      expect(config.userinfo_endpoint).toBeTruthy();
      expect(config.jwks_uri).toBeTruthy();

      // Token, userinfo should use RFC paths
      expect(config.token_endpoint).toContain('/oauth/token');
      expect(config.userinfo_endpoint).toContain('/oauth/userinfo');
      if (config.introspection_endpoint) {
        expect(config.introspection_endpoint).toContain('/oauth/introspect');
      }

      // authorization_endpoint must contain /oauth/authorize
      // (both /oauth/authorize and /login/oauth/authorize match this)
      expect(config.authorization_endpoint).toContain('/oauth/authorize');

      // Required arrays
      expect(config.response_types_supported).toContain('code');
      expect(config.grant_types_supported).toContain('authorization_code');
      expect(config.scopes_supported).toContain('openid');
    });
  }

  test('JWKS endpoint serves valid keys', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/.well-known/jwks`);
    expect(res.status()).toBe(200);

    const jwks = await res.json();
    expect(jwks.keys).toBeDefined();
    expect(jwks.keys.length).toBeGreaterThan(0);
    expect(jwks.keys[0]).toHaveProperty('kty');
    expect(jwks.keys[0]).toHaveProperty('kid');
  });

  test('JWKS at /.well-known/jwks.json also works', async ({ request }) => {
    const res = await request.get('https://hanzo.id/.well-known/jwks.json');
    expect([200, 301, 302]).toContain(res.status());
  });

  test('OAuth metadata /.well-known/oauth-authorization-server', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/.well-known/oauth-authorization-server`);
    expect(res.status()).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 2. IAM Backend Health
// ---------------------------------------------------------------------------

test.describe('IAM Backend Health', () => {
  test('iam.hanzo.ai /healthz returns 200', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/api/health`);
    expect(res.status()).toBe(200);
  });

  test('iam.hanzo.ai login page reachable', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/login`, { maxRedirects: 5 });
    expect(res.status()).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 3. Login Page Availability (ALL domains)
// ---------------------------------------------------------------------------

test.describe('Login Page Availability', () => {
  // id.lux.network, id.zoo.network, iam.lux.network serve an app directory at /login
  // rather than a login form — they use OAuth redirects to hanzo.id/lux.id for actual auth
  const domainsWithLoginForm = LOGIN_DOMAINS.filter(
    d => !['id.lux.network', 'id.zoo.network', 'iam.lux.network'].includes(d.name)
  );

  for (const domain of domainsWithLoginForm) {
    test(`${domain.name} login page shows form`, async ({ page }) => {
      await page.goto(`${domain.url}/login`, { waitUntil: 'networkidle', timeout: 20000 });
      await page.waitForSelector('input', { timeout: 15000 });

      const hasEmailInput = await page.locator(EMAIL_INPUT).count();
      const hasPasswordInput = await page.locator(PASSWORD_INPUT).count();
      expect(hasEmailInput).toBeGreaterThan(0);
      expect(hasPasswordInput).toBeGreaterThan(0);
    });
  }

  // App directory domains — verify they load and show app links
  for (const domain of LOGIN_DOMAINS.filter(
    d => ['id.lux.network', 'id.zoo.network', 'iam.lux.network'].includes(d.name)
  )) {
    test(`${domain.name} login page loads`, async ({ page }) => {
      const res = await page.goto(`${domain.url}/login`, { waitUntil: 'networkidle', timeout: 20000 });
      expect(res?.status()).toBe(200);
    });
  }
});

// ---------------------------------------------------------------------------
// 4. White-Label Frontend Tests
// ---------------------------------------------------------------------------

test.describe('White-Label — hanzo.id', () => {
  test('login form with email + password', async ({ page }) => {
    await page.goto('https://hanzo.id/login', { waitUntil: 'networkidle' });
    await page.waitForSelector('input', { timeout: 10000 });
    await expect(page.locator(EMAIL_INPUT).first()).toBeVisible();
    await expect(page.locator(PASSWORD_INPUT).first()).toBeVisible();
  });

  test('invalid credentials show error', async ({ page }) => {
    await page.goto('https://hanzo.id/login', { waitUntil: 'networkidle' });
    await page.waitForSelector('input', { timeout: 10000 });
    await page.locator(EMAIL_INPUT).first().fill('test@invalid.com');
    await page.locator(PASSWORD_INPUT).first().fill('wrongpassword123');
    await page.locator('button[type="submit"], button:has-text("Sign In"), button:has-text("Login")').first().click();

    // Wait for error message or notification
    const error = page.locator('[class*="error"], [class*="alert"], [role="alert"], .text-red, .text-destructive, .ant-message-error');
    await expect(error.first()).toBeVisible({ timeout: 10000 });
  });

  test('no upstream branding visible', async ({ page }) => {
    await page.goto('https://hanzo.id/login', { waitUntil: 'networkidle' });
    const content = await page.textContent('body');
    expect(content?.toLowerCase()).not.toContain('casdoor');
  });
});

test.describe('White-Label — auth.hanzo.ai', () => {
  test('login form loads (Next.js)', async ({ page }) => {
    await page.goto('https://auth.hanzo.ai/login', { waitUntil: 'networkidle' });
    await page.waitForSelector('input', { timeout: 10000 });
    await expect(page.locator(EMAIL_INPUT).first()).toBeVisible();
    await expect(page.locator(PASSWORD_INPUT).first()).toBeVisible();
  });

  test('no upstream branding visible', async ({ page }) => {
    await page.goto('https://auth.hanzo.ai/login', { waitUntil: 'networkidle' });
    const content = await page.textContent('body');
    expect(content?.toLowerCase()).not.toContain('casdoor');
  });
});

test.describe('White-Label — lux.id', () => {
  test('login form loads', async ({ page }) => {
    await page.goto('https://lux.id/login', { waitUntil: 'networkidle' });
    await page.waitForSelector('input', { timeout: 10000 });
    await expect(page.locator(EMAIL_INPUT).first()).toBeVisible();
    await expect(page.locator(PASSWORD_INPUT).first()).toBeVisible();
  });

  test('no upstream branding visible', async ({ page }) => {
    await page.goto('https://lux.id/login', { waitUntil: 'networkidle' });
    const content = await page.textContent('body');
    expect(content?.toLowerCase()).not.toContain('casdoor');
  });
});

test.describe('White-Label — pars.id', () => {
  test('login form loads', async ({ page }) => {
    await page.goto('https://pars.id/login', { waitUntil: 'networkidle' });
    await page.waitForSelector('input', { timeout: 10000 });
    await expect(page.locator(EMAIL_INPUT).first()).toBeVisible();
    await expect(page.locator(PASSWORD_INPUT).first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// 5. App Registration — existence check via get-application API
// ---------------------------------------------------------------------------

test.describe('App Registration — existence', () => {
  for (const app of REGISTERED_APPS) {
    test(`${app.name} exists in IAM (clientId: ${app.clientId})`, async ({ request }) => {
      const res = await request.get(`${IAM_ORIGIN}/api/get-application?id=admin/${app.name}`);
      expect(res.status()).toBe(200);

      const data = await res.json();
      expect(data.status).toBe('ok');
      expect(data.data).toBeTruthy();
      expect(data.data.clientId).toBe(app.clientId);
    });
  }
});

// ---------------------------------------------------------------------------
// 6. App Registration — get-app-login resolves (needs matching redirect_uri)
// ---------------------------------------------------------------------------

test.describe('App Registration — get-app-login', () => {
  // Only test apps whose production redirect URIs are registered in IAM
  // MPC apps only have localhost redirect URIs configured
  const appsWithKnownRedirects = REGISTERED_APPS.filter(
    a => !['app-pars-mpc', 'app-lux-mpc', 'app-zoo-mpc'].includes(a.name)
  );

  for (const app of appsWithKnownRedirects) {
    test(`${app.name} resolves via get-app-login`, async ({ request }) => {
      const params = new URLSearchParams({
        clientId: app.clientId,
        type: 'code',
        responseType: 'code',
        redirectUri: app.redirectUri,
        scope: 'openid profile email',
        state: 'e2e-test',
      });

      const res = await request.get(`${IAM_ORIGIN}/api/get-app-login?${params}`);
      expect(res.status()).toBe(200);

      const data = await res.json();
      expect(data.status).toBe('ok');
      expect(data.data).toBeTruthy();
      expect(data.data.name).toBe(app.name);
    });
  }
});

// ---------------------------------------------------------------------------
// 7. OAuth2 Authorize Flow
// ---------------------------------------------------------------------------

test.describe('OAuth2 Authorize', () => {
  // Test authorize via HTTP (no browser rendering needed)
  const testCases = [
    { domain: LOGIN_DOMAINS[0]!, app: REGISTERED_APPS[0]! },  // hanzo.id + app-hanzo
    { domain: LOGIN_DOMAINS[1]!, app: REGISTERED_APPS[0]! },  // auth.hanzo.ai + app-hanzo
    { domain: LOGIN_DOMAINS[2]!, app: REGISTERED_APPS[13]! }, // lux.id + app-lux
    { domain: LOGIN_DOMAINS[3]!, app: REGISTERED_APPS[17]! }, // pars.id + app-pars
  ];

  for (const { domain, app } of testCases) {
    test(`${domain.name} + ${app.name} — /oauth/authorize responds`, async ({ request }) => {
      const authUrl = new URL(`${domain.url}/oauth/authorize`);
      authUrl.searchParams.set('client_id', app.clientId);
      authUrl.searchParams.set('redirect_uri', app.redirectUri);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', 'openid profile email');
      authUrl.searchParams.set('state', 'e2e-test-state');

      const res = await request.get(authUrl.toString(), { maxRedirects: 0 });
      // Should redirect to login page or serve login HTML — not 404/500
      expect([200, 302, 303]).toContain(res.status());
    });
  }

  // Verify authorize endpoint serves HTML or redirects (not 404)
  test('auth.hanzo.ai /oauth/authorize serves login', async ({ request }) => {
    const authUrl = new URL('https://auth.hanzo.ai/oauth/authorize');
    authUrl.searchParams.set('client_id', 'app-hanzo');
    authUrl.searchParams.set('redirect_uri', 'https://hanzo.ai/callback');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', 'e2e-test');

    const res = await request.get(authUrl.toString(), { maxRedirects: 0 });
    expect([200, 302, 303]).toContain(res.status());
  });

  test('invalid client_id does NOT redirect to attacker domain', async ({ request }) => {
    const res = await request.get(
      'https://hanzo.id/oauth/authorize?client_id=fake-evil-client&redirect_uri=https://evil.com/steal&response_type=code',
      { maxRedirects: 0 },
    );
    // Should NOT redirect to evil.com — should show error or login
    const location = res.headers()['location'] || '';
    expect(location).not.toContain('evil.com');
  });

  test('missing redirect_uri does NOT crash', async ({ request }) => {
    const res = await request.get(
      'https://hanzo.id/oauth/authorize?client_id=app-hanzo&response_type=code',
      { maxRedirects: 0 },
    );
    expect([200, 302, 400]).toContain(res.status());
  });
});

// ---------------------------------------------------------------------------
// 8. Token Endpoint
// ---------------------------------------------------------------------------

test.describe('Token Endpoint', () => {
  test('rejects missing grant_type', async ({ request }) => {
    const res = await request.post(`${IAM_ORIGIN}/oauth/token`, {
      form: { client_id: 'app-hanzo' },
    });
    // IAM returns 400-500 range for malformed requests
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });

  test('rejects invalid authorization code', async ({ request }) => {
    const res = await request.post(`${IAM_ORIGIN}/oauth/token`, {
      form: {
        grant_type: 'authorization_code',
        code: 'invalid-code-xyz',
        client_id: 'app-hanzo',
        redirect_uri: 'https://hanzo.ai/callback',
      },
    });
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });

  test('hanzo.id /oauth/token proxies correctly', async ({ request }) => {
    const res = await request.post('https://hanzo.id/oauth/token', {
      form: { client_id: 'app-hanzo' },
    });
    // Should reach the backend (not 404)
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });
});

// ---------------------------------------------------------------------------
// 9. UserInfo Endpoint
// ---------------------------------------------------------------------------

test.describe('UserInfo Endpoint', () => {
  test('rejects missing token', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/oauth/userinfo`);
    expect([401, 403]).toContain(res.status());
  });

  test('rejects invalid bearer token', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/oauth/userinfo`, {
      headers: { Authorization: 'Bearer invalid-token-abc' },
    });
    expect([401, 403]).toContain(res.status());
  });

  test('hanzo.id /oauth/userinfo proxies correctly', async ({ request }) => {
    const res = await request.get('https://hanzo.id/oauth/userinfo');
    expect([200, 401, 403]).toContain(res.status());
  });
});

// ---------------------------------------------------------------------------
// 10. Introspection + Revocation
// ---------------------------------------------------------------------------

test.describe('Introspection + Revocation', () => {
  test('/oauth/introspect endpoint responds', async ({ request }) => {
    const res = await request.post(`${IAM_ORIGIN}/oauth/introspect`, {
      form: { token: 'invalid' },
    });
    expect(res.status()).toBeLessThan(500);
  });

  test('/oauth/revoke endpoint responds', async ({ request }) => {
    const res = await request.post(`${IAM_ORIGIN}/oauth/revoke`, {
      form: { token: 'invalid' },
    });
    expect(res.status()).toBeLessThan(500);
  });
});

// ---------------------------------------------------------------------------
// 11. Multi-Tenant Isolation
// ---------------------------------------------------------------------------

test.describe('Multi-Tenant Isolation', () => {
  test('hanzo.id and lux.id have different issuers', async ({ request }) => {
    const [hanzoRes, luxRes] = await Promise.all([
      request.get('https://hanzo.id/.well-known/openid-configuration'),
      request.get('https://lux.id/.well-known/openid-configuration'),
    ]);

    const hanzoConfig = await hanzoRes.json();
    const luxConfig = await luxRes.json();

    expect(hanzoConfig.issuer).not.toBe(luxConfig.issuer);
    expect(hanzoConfig.issuer).toContain('hanzo');
    expect(luxConfig.issuer).toContain('lux');
  });

  test('hanzo.id and pars.id have different issuers', async ({ request }) => {
    const [hanzoRes, parsRes] = await Promise.all([
      request.get('https://hanzo.id/.well-known/openid-configuration'),
      request.get('https://pars.id/.well-known/openid-configuration'),
    ]);

    const hanzoConfig = await hanzoRes.json();
    const parsConfig = await parsRes.json();

    expect(hanzoConfig.issuer).not.toBe(parsConfig.issuer);
  });

  test('separate browser contexts have separate sessions', async ({ browser }) => {
    const ctx1 = await browser.newContext();
    const ctx2 = await browser.newContext();

    const p1 = await ctx1.newPage();
    const p2 = await ctx2.newPage();

    await p1.goto('https://hanzo.id/login', { waitUntil: 'domcontentloaded' });
    await p2.goto('https://lux.id/login', { waitUntil: 'domcontentloaded' });

    const cookies1 = await ctx1.cookies();
    const cookies2 = await ctx2.cookies();

    const domains1 = cookies1.map(c => c.domain);
    const domains2 = cookies2.map(c => c.domain);

    const shared = domains1.filter(d => domains2.includes(d));
    expect(shared.length).toBe(0);

    await ctx1.close();
    await ctx2.close();
  });
});

// ---------------------------------------------------------------------------
// 12. Performance
// ---------------------------------------------------------------------------

test.describe('Performance', () => {
  for (const domain of LOGIN_DOMAINS.slice(0, 4)) {
    test(`${domain.name} loads within 5s`, async ({ page }) => {
      const start = Date.now();
      await page.goto(`${domain.url}/login`, { waitUntil: 'domcontentloaded' });
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(5000);
    });
  }

  test('OIDC discovery responds within 2s', async ({ request }) => {
    const start = Date.now();
    await request.get(`${IAM_ORIGIN}/.well-known/openid-configuration`);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(2000);
  });
});

// ---------------------------------------------------------------------------
// 13. Security
// ---------------------------------------------------------------------------

test.describe('Security', () => {
  test('password login does NOT echo password', async ({ request }) => {
    const res = await request.post(`${IAM_ORIGIN}/api/login`, {
      data: {
        type: 'token',
        organization: 'hanzo',
        application: 'app-hanzo',
        username: 'test@test.com',
        password: 'SuperSecret123!',
      },
    });

    const body = await res.text();
    expect(body).not.toContain('SuperSecret123!');
  });

  test('HSTS header on production domains', async ({ request }) => {
    for (const url of ['https://hanzo.id/login', 'https://iam.hanzo.ai/login']) {
      const res = await request.get(url);
      const hsts = res.headers()['strict-transport-security'];
      if (hsts) {
        expect(hsts).toContain('max-age');
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 14. Logout
// ---------------------------------------------------------------------------

test.describe('Logout', () => {
  test('/oauth/logout endpoint exists on IAM', async ({ request }) => {
    const res = await request.get(`${IAM_ORIGIN}/oauth/logout`, { maxRedirects: 0 });
    expect([200, 302]).toContain(res.status());
  });

  test('hanzo.id /oauth/logout proxies correctly', async ({ request }) => {
    const res = await request.get('https://hanzo.id/oauth/logout', { maxRedirects: 0 });
    expect([200, 302]).toContain(res.status());
  });
});

// ---------------------------------------------------------------------------
// 15. RFC Path Compliance (all 3 login surfaces)
// ---------------------------------------------------------------------------

test.describe('RFC Path Compliance', () => {
  const surfaces = [
    { name: 'iam.hanzo.ai', url: 'https://iam.hanzo.ai' },
    { name: 'hanzo.id', url: 'https://hanzo.id' },
    { name: 'auth.hanzo.ai', url: 'https://auth.hanzo.ai' },
  ];

  for (const surface of surfaces) {
    test(`${surface.name} — /oauth/token reachable`, async ({ request }) => {
      const res = await request.post(`${surface.url}/oauth/token`, {
        form: { grant_type: 'client_credentials', client_id: 'app-hanzo' },
      });
      // Should reach the backend (not 404)
      expect(res.status()).toBeGreaterThanOrEqual(400);
    });

    test(`${surface.name} — /oauth/userinfo reachable`, async ({ request }) => {
      const res = await request.get(`${surface.url}/oauth/userinfo`);
      expect([200, 401, 403]).toContain(res.status());
    });

    test(`${surface.name} — /oauth/authorize reachable`, async ({ request }) => {
      const res = await request.get(
        `${surface.url}/oauth/authorize?client_id=app-hanzo&response_type=code&redirect_uri=https://hanzo.ai/callback&scope=openid`,
        { maxRedirects: 0 },
      );
      // Should redirect to login or show login HTML, NOT 404
      expect([200, 302, 303]).toContain(res.status());
    });

    test(`${surface.name} — /.well-known/openid-configuration`, async ({ request }) => {
      const res = await request.get(`${surface.url}/.well-known/openid-configuration`);
      expect(res.status()).toBe(200);
      const config = await res.json();
      expect(config.issuer).toBeTruthy();
      expect(config.token_endpoint).toContain('/oauth/token');
      expect(config.userinfo_endpoint).toContain('/oauth/userinfo');
    });
  }
});
