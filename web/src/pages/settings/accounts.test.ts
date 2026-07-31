import { renderToStaticMarkup } from 'react-dom/server'
import { createElement } from 'react'
import { describe, expect, it, vi } from 'vitest'

vi.mock('@/features/auth/account-merge-wizard', () => ({
  AccountMergeWizard: () =>
    createElement('div', null, 'account-merge-wizard'),
}))

import { AccountSettingsPage } from './accounts'

describe('AccountSettingsPage', () => {
  it('renders the secure account merge wizard', () => {
    const html = renderToStaticMarkup(
      createElement(AccountSettingsPage),
    )

    expect(html).toContain('account-merge-wizard')
  })
})
