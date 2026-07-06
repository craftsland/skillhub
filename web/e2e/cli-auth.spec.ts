import { expect, test } from '@playwright/test'
import { setEnglishLocale } from './helpers/auth-fixtures'

test.describe('CLI Auth (Real API)', () => {
  test.beforeEach(async ({ page }) => {
    await setEnglishLocale(page)
  })

  test('shows legacy callback notice and sends users to device authorization', async ({ page }) => {
    await page.goto('/cli/auth')

    await expect(page.getByRole('heading', { name: 'Use device authorization' })).toBeVisible()
    await page.getByRole('button', { name: 'Open Device Authorization' }).click()

    await expect(page).toHaveURL(/\/login\?returnTo=%2Fdevice$/)
  })

  test('redirects anonymous users from device authorization to login', async ({ page }) => {
    await page.goto('/device')

    await expect(page).toHaveURL(/\/login\?returnTo=%2Fdevice$/)
  })

  test('shows device authorization form for authenticated users', async ({ page }) => {
    await page.context().setExtraHTTPHeaders({
      'X-Mock-User-Id': 'local-user',
    })

    await page.goto('/device')

    await expect(page.getByRole('heading', { name: 'Device Authorization' })).toBeVisible()
    await expect(page.getByText('User Code', { exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Authorize Device' })).toBeVisible()
  })
})
