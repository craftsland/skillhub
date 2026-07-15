import { expect, test, type Route } from '@playwright/test'
import { setEnglishLocale } from './helpers/auth-fixtures'

function apiEnvelope(data: unknown) {
  return {
    code: 0,
    msg: 'OK',
    data,
    timestamp: '2026-07-15T00:00:00Z',
    requestId: 'e2e-super-admin-namespaces',
  }
}

async function fulfillJson(route: Route, data: unknown) {
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(apiEnvelope(data)),
  })
}

test.describe('My Namespaces super admin actions', () => {
  test.beforeEach(async ({ page }) => {
    await setEnglishLocale(page)

    await page.route('**/api/v1/auth/me', (route) => fulfillJson(route, {
      userId: 'super-admin',
      username: 'super-admin',
      displayName: 'Super Admin',
      platformRoles: ['SUPER_ADMIN'],
    }))

    await page.route('**/api/web/notifications/sse', (route) => route.fulfill({
      status: 204,
      body: '',
    }))

    await page.route('**/api/web/notifications/unread-count', (route) => fulfillJson(route, { count: 0 }))

    await page.route('**/api/web/me/namespaces', (route) => fulfillJson(route, [
      {
        id: 101,
        slug: 'visible-no-role',
        displayName: 'Visible Without Membership',
        description: 'Returned by SUPER_ADMIN namespace visibility',
        type: 'TEAM',
        status: 'ACTIVE',
        createdAt: '2026-07-15T00:00:00Z',
        immutable: false,
        canFreeze: false,
        canUnfreeze: false,
        canArchive: false,
        canRestore: false,
        canDelete: false,
      },
      {
        id: 102,
        slug: 'owned-team',
        displayName: 'Owned Team',
        description: 'Namespace where the user is a member',
        type: 'TEAM',
        status: 'ACTIVE',
        createdAt: '2026-07-15T00:00:00Z',
        currentUserRole: 'OWNER',
        immutable: false,
        canFreeze: true,
        canUnfreeze: false,
        canArchive: true,
        canRestore: false,
        canDelete: true,
      },
    ]))
  })

  test('hides namespace-scoped actions for visible namespaces without membership', async ({ page }) => {
    await page.goto('/dashboard/namespaces')

    const visibleCard = page.getByTestId('namespace-card-visible-no-role')
    await expect(visibleCard.getByText('@visible-no-role')).toBeVisible()
    await expect(visibleCard.getByText('Current role: Unknown')).toBeVisible()
    await expect(visibleCard.getByRole('button', { name: 'Manage Members' })).toHaveCount(0)
    await expect(visibleCard.getByRole('button', { name: 'Review Tasks' })).toHaveCount(0)

    const ownedCard = page.getByTestId('namespace-card-owned-team')
    await expect(ownedCard.getByRole('button', { name: 'Manage Members' })).toBeVisible()
    await expect(ownedCard.getByRole('button', { name: 'Review Tasks' })).toBeVisible()
  })
})
