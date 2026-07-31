import { describe, expect, it } from 'vitest'
import type { AuthMethod } from '@/api/types'
import {
  isBrowserLoginMethod,
  LoginButton,
  providerLogoSource,
} from './login-button'

function method(methodType: string): AuthMethod {
  return {
    id: methodType,
    methodType,
    provider: 'cas-main',
    displayName: 'Corporate CAS',
    actionUrl: '/api/v1/auth/cas/cas-main/login',
  }
}

describe('login-button browser method projection', () => {
  it('exports LoginButton component', () => {
    expect(LoginButton).toBeTypeOf('function')
  })

  it('accepts OAuth and CAS redirect methods only', () => {
    expect(isBrowserLoginMethod(method('OAUTH_REDIRECT'))).toBe(true)
    expect(isBrowserLoginMethod(method('CAS_REDIRECT'))).toBe(true)
    expect(isBrowserLoginMethod(method('PASSWORD'))).toBe(false)
  })

  it('uses bundled logos only for providers that have one', () => {
    expect(providerLogoSource('GitHub')).toBe('/github-logo.svg')
    expect(providerLogoSource('gitlab')).toBe('/gitlab-logo.svg')
    expect(providerLogoSource('cas-main')).toBeNull()
    expect(providerLogoSource('corp-oidc')).toBeNull()
  })
})
