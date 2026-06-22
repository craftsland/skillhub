import { expect, test, type Page } from '@playwright/test'
import { setEnglishLocale } from './helpers/auth-fixtures'

type AuthUser = {
  userId: string
  displayName: string
  email: string
  avatarUrl: string
  oauthProvider?: string
  platformRoles: string[]
}

function apiEnvelope(data: unknown) {
  return {
    code: 0,
    msg: 'ok',
    data,
    timestamp: new Date().toISOString(),
    requestId: 'user-menu-security-settings',
  }
}

async function mockSession(page: Page, user: AuthUser) {
  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(apiEnvelope(user)),
    })
  })

  await page.route('**/api/web/me/namespaces', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(apiEnvelope([])),
    })
  })

  await page.route('**/api/web/notifications/unread-count', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(apiEnvelope({ count: 0 })),
    })
  })

  await page.route('**/api/web/notifications/sse', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/event-stream',
      body: '',
    })
  })
}

async function openUserMenu(page: Page, displayName: string) {
  await page.goto('/settings/security')
  await expect(page.getByRole('heading', { name: 'Security Settings' })).toBeVisible()
  await page.getByRole('button', { name: displayName }).click()
  await expect(page.getByRole('menu')).toBeVisible()
}

test.describe('User menu security settings visibility', () => {
  test.use({ baseURL: 'http://127.0.0.1:3000' })

  test.beforeEach(async ({ page }) => {
    await setEnglishLocale(page)
  })

  test('shows security settings for local password accounts', async ({ page }) => {
    await mockSession(page, {
      userId: 'docker-admin',
      displayName: 'Platform Admin',
      email: 'admin@skillhub.local',
      avatarUrl: '',
      oauthProvider: 'local',
      platformRoles: ['SUPER_ADMIN'],
    })

    await openUserMenu(page, 'Platform Admin')

    await expect(page.getByRole('menu').getByRole('link', { name: 'Security Settings' })).toBeVisible()
  })

  test('hides security settings for OAuth provider accounts', async ({ page }) => {
    await mockSession(page, {
      userId: 'oauth-admin',
      displayName: 'OAuth Admin',
      email: 'oauth-admin@example.com',
      avatarUrl: '',
      oauthProvider: 'github',
      platformRoles: ['SUPER_ADMIN'],
    })

    await openUserMenu(page, 'OAuth Admin')

    await expect(page.getByRole('menu').getByRole('link', { name: 'Security Settings' })).toHaveCount(0)
  })
})
