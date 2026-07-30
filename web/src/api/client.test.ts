import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const originalWindow = globalThis.window
const originalDocument = globalThis.document

function setMockWindow(runtimeConfig?: Window['__SKILLHUB_RUNTIME_CONFIG__']) {
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    writable: true,
    value: {
      __SKILLHUB_RUNTIME_CONFIG__: runtimeConfig,
    } satisfies Pick<Window, '__SKILLHUB_RUNTIME_CONFIG__'>,
  })
}

// Mock i18n before importing client
vi.mock('@/i18n/config', () => ({
  default: { resolvedLanguage: 'en' },
}))

// Mock api-error before importing client
vi.mock('@/shared/lib/api-error', () => ({
  ApiError: class ApiError extends Error {
    status: number
    serverMessage?: string
    serverMessageKey?: string
    reasonCode?: string
    constructor(
      message: string,
      status: number,
      serverMessage?: string,
      serverMessageKey?: string,
      reasonCode?: string,
    ) {
      super(message)
      this.status = status
      this.serverMessage = serverMessage
      this.serverMessageKey = serverMessageKey
      this.reasonCode = reasonCode
    }
  },
  handleApiError: vi.fn(),
}))

import {
  WEB_API_PREFIX,
  buildApiUrl,
  fetchText,
  getDirectAuthRuntimeConfig,
  getSessionBootstrapRuntimeConfig,
  identityLinkApi,
  namespaceApi,
} from './client'

beforeEach(() => {
  setMockWindow()
})

afterEach(() => {
  vi.unstubAllGlobals()

  if (originalDocument) {
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      writable: true,
      value: originalDocument,
    })
  } else {
    Reflect.deleteProperty(globalThis, 'document')
  }

  if (originalWindow) {
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      writable: true,
      value: originalWindow,
    })
    return
  }

  Reflect.deleteProperty(globalThis, 'window')
})

describe('WEB_API_PREFIX', () => {
  it('uses the /api/web prefix for web-facing endpoints', () => {
    expect(WEB_API_PREFIX).toBe('/api/web')
  })
})

describe('buildApiUrl', () => {
  it('returns the path as-is when no runtime base URL is configured', () => {
    expect(buildApiUrl('/api/v1/auth/me')).toBe('/api/v1/auth/me')
  })

  it('prepends the runtime base URL when one is set', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = { apiBaseUrl: 'https://api.example.com' }
    const url = buildApiUrl('/api/v1/auth/me')
    expect(url).toBe('https://api.example.com/api/v1/auth/me')
  })

  it('handles a trailing slash on the base URL', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = { apiBaseUrl: 'https://api.example.com/' }
    const url = buildApiUrl('/api/v1/auth/me')
    expect(url).toBe('https://api.example.com/api/v1/auth/me')
  })

  it('preserves base URL path prefixes', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = { apiBaseUrl: 'https://api.example.com/skill_hub' }
    const url = buildApiUrl('/api/v1/auth/me')
    expect(url).toBe('https://api.example.com/skill_hub/api/v1/auth/me')
  })

  it('supports relative base URL path prefixes', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = { apiBaseUrl: '/skill_hub' }
    const url = buildApiUrl('/api/v1/auth/me')
    expect(url).toBe('/skill_hub/api/v1/auth/me')
  })
})

describe('fetchText', () => {
  it('applies base URL path prefixes for fetch requests', async () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = { apiBaseUrl: 'https://api.example.com/skill_hub' }
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => 'ok',
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchText('/api/v1/auth/me')

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.example.com/skill_hub/api/v1/auth/me',
      expect.objectContaining({
        headers: expect.any(Headers),
      }),
    )
  })
})

describe('namespaceApi.delete', () => {
  it('sends a DELETE request to the normalized namespace endpoint', async () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = { apiBaseUrl: 'https://api.example.com' }
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      writable: true,
      value: {
        cookie: 'XSRF-TOKEN=test-token',
      },
    })

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        code: 0,
        msg: 'ok',
        data: null,
        timestamp: '2026-05-07T00:00:00Z',
        requestId: 'req-test',
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await namespaceApi.delete('@team-delete')

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.example.com/api/web/namespaces/team-delete',
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.any(Headers),
      }),
    )
  })
})

describe('identityLinkApi', () => {
  it('normalizes the login-method account state', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        code: 0,
        msg: 'ok',
        data: {
          localPasswordEnabled: true,
          linkedProviders: [{
            bindingId: 41,
            providerCode: 'github',
            displayName: 'GitHub',
            methodTypes: ['OAUTH_REDIRECT'],
            usable: true,
            canUnlink: true,
          }],
          availableProviders: [{
            providerCode: 'oidc',
            displayName: 'Company OIDC',
            methodTypes: ['OAUTH_REDIRECT'],
          }],
        },
        timestamp: '2026-07-31T00:00:00Z',
        requestId: 'req-identity-link',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(identityLinkApi.getAccountState()).resolves.toEqual({
      localPasswordEnabled: true,
      linkedProviders: [{
        bindingId: 41,
        providerCode: 'github',
        displayName: 'GitHub',
        methodTypes: ['OAUTH_REDIRECT'],
        usable: true,
        canUnlink: true,
      }],
      availableProviders: [{
        providerCode: 'oidc',
        displayName: 'Company OIDC',
        methodTypes: ['OAUTH_REDIRECT'],
      }],
    })
  })

  it('creates a session-bound link intent with CSRF protection', async () => {
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      writable: true,
      value: {
        cookie: 'XSRF-TOKEN=identity-link-csrf',
      },
    })
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        code: 0,
        msg: 'ok',
        data: {
          id: 'a0b89f51-a892-4b73-bdac-63df2cb14691',
          operation: 'LINK',
          status: 'PENDING_REAUTHENTICATION',
          providerCode: 'github',
          expiresAt: '2026-07-31T00:10:00Z',
        },
        timestamp: '2026-07-31T00:00:00Z',
        requestId: 'req-identity-link',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const intent = await identityLinkApi.createLinkIntent('github')

    expect(intent.status).toBe('PENDING_REAUTHENTICATION')
    const request = fetchMock.mock.calls[0]?.[0] as Request
    expect(request.url).toBe(
      'http://localhost/api/v1/auth/identity-link-intents/link',
    )
    expect(request.method).toBe('POST')
    await expect(request.clone().json()).resolves.toEqual({
      providerCode: 'github',
    })
    expect(request.headers.get('X-XSRF-TOKEN'))
      .toBe('identity-link-csrf')
  })

  it('preserves stable identity-link failure reason codes', async () => {
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      writable: true,
      value: {
        cookie: 'XSRF-TOKEN=identity-link-csrf',
      },
    })
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        code: 409,
        msg: 'Keep another login method.',
        reasonCode: 'FINAL_LOGIN_METHOD',
        timestamp: '2026-07-31T00:00:00Z',
        requestId: 'req-identity-link-error',
      }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      identityLinkApi.completeUnlink(
        'a0b89f51-a892-4b73-bdac-63df2cb14691',
      ),
    ).rejects.toMatchObject({
      status: 409,
      reasonCode: 'FINAL_LOGIN_METHOD',
    })
  })
})

describe('getDirectAuthRuntimeConfig', () => {
  it('returns disabled when no runtime config is present', () => {
    const config = getDirectAuthRuntimeConfig()
    expect(config.enabled).toBe(false)
    expect(config.provider).toBeUndefined()
  })

  it('returns enabled with provider when both flag and provider are set', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = {
      authDirectEnabled: 'true',
      authDirectProvider: 'ldap',
    }
    const config = getDirectAuthRuntimeConfig()
    expect(config.enabled).toBe(true)
    expect(config.provider).toBe('ldap')
  })

  it('returns disabled when the flag is true but the provider is missing', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = {
      authDirectEnabled: 'true',
    }
    const config = getDirectAuthRuntimeConfig()
    expect(config.enabled).toBe(false)
  })

  it('returns disabled when the flag is false', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = {
      authDirectEnabled: 'false',
      authDirectProvider: 'ldap',
    }
    const config = getDirectAuthRuntimeConfig()
    expect(config.enabled).toBe(false)
  })

  it('treats various truthy flag values correctly', () => {
    for (const flag of ['1', 'yes', 'on', 'TRUE', ' True ']) {
      window.__SKILLHUB_RUNTIME_CONFIG__ = {
        authDirectEnabled: flag,
        authDirectProvider: 'ldap',
      }
      expect(getDirectAuthRuntimeConfig().enabled).toBe(true)
    }
  })
})

describe('getSessionBootstrapRuntimeConfig', () => {
  it('returns disabled when no runtime config is present', () => {
    const config = getSessionBootstrapRuntimeConfig()
    expect(config.enabled).toBe(false)
    expect(config.auto).toBe(false)
    expect(config.provider).toBeUndefined()
  })

  it('returns fully enabled config when all flags and provider are set', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = {
      authSessionBootstrapEnabled: '1',
      authSessionBootstrapProvider: 'sso',
      authSessionBootstrapAuto: 'true',
    }
    const config = getSessionBootstrapRuntimeConfig()
    expect(config.enabled).toBe(true)
    expect(config.provider).toBe('sso')
    expect(config.auto).toBe(true)
  })

  it('returns disabled when the provider is blank', () => {
    window.__SKILLHUB_RUNTIME_CONFIG__ = {
      authSessionBootstrapEnabled: 'true',
      authSessionBootstrapProvider: '  ',
    }
    const config = getSessionBootstrapRuntimeConfig()
    expect(config.enabled).toBe(false)
  })
})
