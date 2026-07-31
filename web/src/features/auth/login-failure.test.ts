import { describe, expect, it } from 'vitest'
import { loginFailureMessageKey } from './login-failure'

describe('login failure messages', () => {
  it('maps stable CAS failure reasons to localized messages', () => {
    expect(loginFailureMessageKey('casInvalidState'))
      .toBe('login.failure.casInvalidState')
    expect(loginFailureMessageKey('casValidationFailed'))
      .toBe('login.failure.casValidationFailed')
    expect(loginFailureMessageKey('casUnavailable'))
      .toBe('login.failure.casUnavailable')
  })

  it('does not render untrusted reason text', () => {
    expect(loginFailureMessageKey('<script>alert(1)</script>'))
      .toBeUndefined()
    expect(loginFailureMessageKey()).toBeUndefined()
  })
})
