import { describe, expect, it } from 'vitest'
import { canShowSecuritySettings } from './user-menu'

describe('canShowSecuritySettings', () => {
  it('allows local password accounts to open security settings', () => {
    expect(canShowSecuritySettings({ oauthProvider: 'local' })).toBe(true)
  })

  it('keeps security settings hidden for OAuth provider accounts', () => {
    expect(canShowSecuritySettings({ oauthProvider: 'github' })).toBe(false)
  })
})
