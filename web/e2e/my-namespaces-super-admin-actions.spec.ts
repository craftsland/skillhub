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

    await page.route('**/api/web/skills/*/star', (route) => fulfillJson(route, false))

    await page.route('**/api/web/me/namespaces?**', (route) => fulfillJson(route, {
      items: [
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
        {
          id: 103,
          slug: 'archived-no-role',
          displayName: 'Archived Without Membership',
          description: 'Archived namespace visible to SUPER_ADMIN',
          type: 'TEAM',
          status: 'ARCHIVED',
          createdAt: '2026-07-15T00:00:00Z',
          immutable: false,
          canFreeze: false,
          canUnfreeze: false,
          canArchive: false,
          canRestore: false,
          canDelete: false,
        },
      ],
      page: 0,
      size: 20,
      total: 3,
    }))

    await page.route('**/api/web/namespaces/visible-no-role', (route) => fulfillJson(route, {
      id: 101,
      slug: 'visible-no-role',
      displayName: 'Visible Without Membership',
      description: 'Returned by SUPER_ADMIN namespace visibility',
      type: 'TEAM',
      status: 'ACTIVE',
      createdAt: '2026-07-15T00:00:00Z',
    }))

    await page.route('**/api/web/namespaces/archived-no-role', (route) => fulfillJson(route, {
      id: 103,
      slug: 'archived-no-role',
      displayName: 'Archived Without Membership',
      description: 'Archived namespace visible to SUPER_ADMIN',
      type: 'TEAM',
      status: 'ARCHIVED',
      createdAt: '2026-07-15T00:00:00Z',
    }))

    await page.route('**/api/web/skills?**', (route) => {
      const url = new URL(route.request().url())
      if (url.searchParams.get('namespace') === 'archived-no-role') {
        return fulfillJson(route, {
          items: [
            {
              id: 301,
              slug: 'archived-skill',
              displayName: 'Archived Namespace Skill',
              summary: 'Visible when archived namespace read semantics are consistent',
              visibility: 'PUBLIC',
              status: 'ACTIVE',
              namespace: 'archived-no-role',
              downloadCount: 0,
              starCount: 0,
              ratingCount: 0,
              updatedAt: '2026-07-15T00:00:00Z',
              publishedVersion: { id: 401, version: '1.0.0', status: 'PUBLISHED' },
            },
          ],
          page: 0,
          size: 20,
          total: 1,
        })
      }
      return fulfillJson(route, {
        items: [],
        page: 0,
        size: 20,
        total: 0,
      })
    })
  })

  test('keeps namespace-scoped actions hidden and opens detail for visible namespaces without membership', async ({ page }) => {
    await page.goto('/dashboard/namespaces')

    const visibleCard = page.getByTestId('namespace-card-visible-no-role')
    await expect(visibleCard.getByText('@visible-no-role')).toBeVisible()
    await expect(visibleCard.getByText('Current role: Unknown')).toBeVisible()
    await expect(visibleCard.getByRole('button', { name: 'Manage Members' })).toHaveCount(0)
    await expect(visibleCard.getByRole('button', { name: 'Review Tasks' })).toHaveCount(0)

    const ownedCard = page.getByTestId('namespace-card-owned-team')
    await expect(ownedCard.getByRole('button', { name: 'Manage Members' })).toBeVisible()
    await expect(ownedCard.getByRole('button', { name: 'Review Tasks' })).toBeVisible()

    await visibleCard.click()

    await expect(page).toHaveURL(/\/space\/visible-no-role$/)
    await expect(page.getByRole('heading', { name: 'Visible Without Membership' })).toBeVisible()
    await expect(page.getByText('@visible-no-role')).toBeVisible()
  })

  test('opens archived non-member namespaces without showing a false empty skill list', async ({ page }) => {
    await page.goto('/dashboard/namespaces')

    const archivedCard = page.getByTestId('namespace-card-archived-no-role')
    await expect(archivedCard.getByText('@archived-no-role')).toBeVisible()
    await expect(archivedCard.getByText('Current role: Unknown')).toBeVisible()
    await expect(archivedCard.getByRole('button', { name: 'Manage Members' })).toHaveCount(0)
    await expect(archivedCard.getByRole('button', { name: 'Review Tasks' })).toHaveCount(0)

    await archivedCard.click()

    await expect(page).toHaveURL(/\/space\/archived-no-role$/)
    await expect(page.getByRole('heading', { name: 'Archived Without Membership' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Archived Namespace Skill' })).toBeVisible()
    await expect(page.getByText('namespace.emptyTitle')).toHaveCount(0)
  })
})
