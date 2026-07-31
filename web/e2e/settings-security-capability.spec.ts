import { expect, test, type Page } from '@playwright/test'
import { setEnglishLocale } from './helpers/auth-fixtures'
import { csrfHeaders } from './helpers/csrf'
import { createFreshSession, loginWithCredentials } from './helpers/session'

function getOptionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim()
  return value ? value : undefined
}

function adminCredentials() {
  return {
    username: getOptionalEnv('E2E_ADMIN_USERNAME') ?? getOptionalEnv('BOOTSTRAP_ADMIN_USERNAME') ?? 'admin',
    password: getOptionalEnv('E2E_ADMIN_PASSWORD') ?? getOptionalEnv('BOOTSTRAP_ADMIN_PASSWORD') ?? 'ChangeMe!2026',
  }
}

function gitLabIdentityLinkE2EEnabled(): boolean {
  return getOptionalEnv('E2E_IDENTITY_LINK_BROWSER_PROVIDER') === 'gitlab'
}

function requireGitLabIdentityLinkE2E(): void {
  const enabled = gitLabIdentityLinkE2EEnabled()
  if (!enabled && process.env.CI) {
    throw new Error(
      'E2E_IDENTITY_LINK_BROWSER_PROVIDER=gitlab is required in CI',
    )
  }
  test.skip(!enabled, 'requires the dedicated GitLab identity-link test provider')
}

async function currentDisplayName(page: Page, headers?: Record<string, string>): Promise<string> {
  const response = await page.context().request.get('/api/v1/auth/me', { headers })
  expect(response.ok()).toBeTruthy()
  const body = await response.json() as { data: { displayName: string } }
  return body.data.displayName
}

test.describe('Security Settings capability (Real API)', () => {
  test.use({
    baseURL: getOptionalEnv('E2E_BASE_URL') ?? 'http://127.0.0.1:3000',
  })

  test('shows the security menu entry and password form for local admin accounts', async ({ page }, testInfo) => {
    await setEnglishLocale(page)
    await loginWithCredentials(page, adminCredentials(), testInfo)
    const displayName = await currentDisplayName(page)

    await page.goto('/settings/security')
    await expect(page.getByRole('heading', { name: 'Security Settings' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Login Methods', exact: true })).toBeVisible()
    await expect(page.getByText('Local password', { exact: true }).first()).toBeVisible()
    await expect(page.getByLabel('Current Password')).toBeVisible()
    await expect(page.getByLabel('New Password')).toBeVisible()

    await page.getByRole('button', { name: displayName }).click()
    await expect(page.getByRole('link', { name: 'Security Settings' })).toBeVisible()
  })

  test('requires fresh local reauthentication before linking an external provider', async ({ page }, testInfo) => {
    requireGitLabIdentityLinkE2E()
    await setEnglishLocale(page)
    const credentials = await createFreshSession(page, testInfo)

    await page.goto('/settings/security')
    await expect(page.getByRole('heading', { name: 'Login Methods', exact: true })).toBeVisible()
    const addButton = page.getByRole('button', { name: 'Add' }).first()
    await expect(addButton).toBeVisible()
    await addButton.click()

    const dialog = page.getByRole('dialog', { name: 'Verify account control' })
    await expect(dialog).toBeVisible()
    await dialog.getByLabel('Local password').fill(credentials.password)
    await dialog.getByRole('button', { name: 'Verify password' }).click()

    await expect(dialog.getByText(
      'Current account verified. Now authenticate the login method you want to link.',
    )).toBeVisible()
    await expect(dialog.getByRole('button', { name: /^Continue with / })).toBeVisible()

    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await expect(dialog).toBeHidden()
  })

  test('links, unlinks, and relinks a browser identity through the deployed stack', async ({ page }, testInfo) => {
    requireGitLabIdentityLinkE2E()
    await setEnglishLocale(page)
    const credentials = await createFreshSession(page, testInfo)
    await page.goto('/settings/security')

    const availableMethods = page.locator(
      'section[aria-labelledby="available-login-methods"]',
    )
    const linkedMethods = page.locator(
      'section[aria-labelledby="linked-login-methods"]',
    )

    async function linkGitLab() {
      await expect(availableMethods.getByText('GitLab', { exact: true })).toBeVisible()
      await availableMethods.getByRole('button', { name: 'Add' }).click()
      const dialog = page.getByRole('dialog', { name: 'Verify account control' })
      await dialog.getByLabel('Local password').fill(credentials.password)
      await dialog.getByRole('button', { name: 'Verify password' }).click()
      await expect(dialog.getByRole('button', { name: 'Continue with GitLab' })).toBeVisible()
      await dialog.getByRole('button', { name: 'Continue with GitLab' }).click()
      await page.waitForURL(/identityLink=linked/)
      await expect(page.getByText('The login method was linked successfully.')).toBeVisible()
      await expect(linkedMethods.getByText('GitLab', { exact: true })).toBeVisible()
    }

    await linkGitLab()

    await linkedMethods.getByRole('button', { name: 'Remove' }).click()
    const unlinkDialog = page.getByRole('dialog', { name: 'Verify account control' })
    await unlinkDialog.getByLabel('Local password').fill(credentials.password)
    await unlinkDialog.getByRole('button', { name: 'Verify password' }).click()
    await expect(
      unlinkDialog.getByRole('button', { name: 'Remove login method' }),
    ).toBeVisible()
    await unlinkDialog.getByRole('button', { name: 'Remove login method' }).click()
    await expect(unlinkDialog).toBeHidden()
    await expect(availableMethods.getByText('GitLab', { exact: true })).toBeVisible()

    await linkGitLab()
  })

  test('redirects an unavailable identity-link provider with a stable reason code', async ({ page }, testInfo) => {
    requireGitLabIdentityLinkE2E()
    await setEnglishLocale(page)
    const credentials = await createFreshSession(page, testInfo)
    const request = page.context().request

    const createIntent = await request.post('/api/v1/auth/identity-link-intents/link', {
      data: { providerCode: 'gitlab' },
      headers: await csrfHeaders(page),
    })
    expect(createIntent.ok()).toBeTruthy()
    const createBody = await createIntent.json() as { data: { id: string } }
    const intentId = createBody.data.id

    const reauthenticate = await request.post(
      `/api/v1/auth/identity-link-intents/${intentId}/reauthenticate/local`,
      {
        data: { password: credentials.password },
        headers: await csrfHeaders(page),
      },
    )
    expect(reauthenticate.ok()).toBeTruthy()

    const prepareLink = await request.post(
      `/api/v1/auth/identity-link-intents/${intentId}/link/browser`,
      { headers: await csrfHeaders(page) },
    )
    expect(prepareLink.ok()).toBeTruthy()
    const prepareBody = await prepareLink.json() as { data: { actionUrl: string } }
    const unavailableActionUrl = prepareBody.data.actionUrl.replace(
      '/oauth2/authorization/gitlab',
      '/oauth2/authorization/missing-provider',
    )
    expect(unavailableActionUrl).not.toBe(prepareBody.data.actionUrl)

    const failure = await request.get(unavailableActionUrl, { maxRedirects: 0 })
    expect(failure.status()).toBe(302)
    const location = failure.headers().location
    expect(location).toBeTruthy()
    const redirect = new URL(location, 'http://127.0.0.1')
    expect(redirect.pathname).toBe('/settings/security')
    expect(redirect.searchParams.get('identityLink')).toBe('failed')
    expect(redirect.searchParams.get('intentId')).toBe(intentId)
    expect(redirect.searchParams.get('reasonCode')).toBe('PROVIDER_UNAVAILABLE')

    const ordinaryOAuth = await request.get(
      '/oauth2/authorization/missing-provider',
      { maxRedirects: 0 },
    )
    expect(ordinaryOAuth.status()).toBe(403)
  })

  test('hides the security menu entry and rejects password changes without a local credential', async ({ page }) => {
    await setEnglishLocale(page)
    await page.context().setExtraHTTPHeaders({
      'X-Mock-User-Id': 'local-user',
    })
    const displayName = await currentDisplayName(page, { 'X-Mock-User-Id': 'local-user' })

    await page.goto('/settings/security')

    await expect(page.getByRole('heading', { name: 'Security Settings' })).toBeVisible()
    await expect(page.getByText('Password changes are unavailable for this account.')).toBeVisible()
    await expect(page.getByLabel('Current Password')).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Update Password' })).toHaveCount(0)

    await page.getByRole('button', { name: displayName }).click()
    await expect(page.getByRole('link', { name: 'Security Settings' })).toHaveCount(0)

    const response = await page.context().request.post('/api/v1/auth/local/change-password', {
      data: {
        currentPassword: 'Passw0rd!123',
        newPassword: 'N3wPassw0rd!123',
      },
      headers: await csrfHeaders(page, { 'X-Mock-User-Id': 'local-user' }),
    })
    expect(response.status()).toBe(400)
  })
})
