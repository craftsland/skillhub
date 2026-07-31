import { expect, test } from '@playwright/test'
import { setEnglishLocale } from './helpers/auth-fixtures'
import { registerSession } from './helpers/session'

test.describe('Settings Routing (Real API)', () => {
  test.beforeEach(async ({ page }, testInfo) => {
    await setEnglishLocale(page)
    await registerSession(page, testInfo)
  })

  test('keeps the accounts route and renders its capability state', async ({ page }) => {
    await page.goto('/settings/accounts')
    await expect(page).toHaveURL('/settings/accounts')
    await expect(page.getByRole('heading', {
      name: /Account merging|Merge accounts/,
    })).toBeVisible()
  })
})
