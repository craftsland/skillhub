import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IdentityLinkAccountState } from '@/api/types'

let accountState: IdentityLinkAccountState

function mutation() {
  return {
    isPending: false,
    mutateAsync: vi.fn(),
  }
}

vi.mock('react-i18next', async () => {
  const actual = await vi.importActual<typeof import('react-i18next')>(
    'react-i18next',
  )
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => key,
    }),
  }
})

vi.mock('@/api/client', () => ({
  buildApiUrl: (value: string) => value,
}))

vi.mock('./use-identity-links', () => ({
  useIdentityLinkAccountState: () => ({
    data: accountState,
    isLoading: false,
    error: null,
  }),
  useIdentityLinkIntent: () => ({
    data: undefined,
    isLoading: false,
    error: null,
  }),
  useIdentityLinkActions: () => ({
    createLink: mutation(),
    createUnlink: mutation(),
    cancel: mutation(),
    reauthenticateLocal: mutation(),
    prepareBrowserReauthentication: mutation(),
    reauthenticateCredential: mutation(),
    prepareBrowserLink: mutation(),
    linkCredential: mutation(),
    completeUnlink: mutation(),
  }),
}))

import {
  IdentityLinkManager,
  parseIdentityLinkCallback,
  resumableIdentityLinkIntentId,
} from './identity-link-manager'

beforeEach(() => {
  vi.stubGlobal('window', {
    location: {
      search: '',
      assign: vi.fn(),
    },
  })
  accountState = {
    localPasswordEnabled: true,
    linkedProviders: [
      {
        bindingId: 41,
        providerCode: 'github',
        displayName: 'GitHub',
        methodTypes: ['OAUTH_REDIRECT'],
        usable: true,
        canUnlink: true,
      },
    ],
    availableProviders: [
      {
        providerCode: 'oidc',
        displayName: 'Company OIDC',
        methodTypes: ['OAUTH_REDIRECT'],
      },
    ],
  }
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('parseIdentityLinkCallback', () => {
  it('accepts only supported callback results', () => {
    expect(parseIdentityLinkCallback(
      '?identityLink=reauthenticated&intentId=intent-1',
    )).toEqual({
      result: 'reauthenticated',
      intentId: 'intent-1',
    })
    expect(parseIdentityLinkCallback(
      '?identityLink=unexpected&intentId=intent-1',
    )).toEqual({})
    expect(parseIdentityLinkCallback(
      '?identityLink=failed&intentId=intent-1&reasonCode=PROVIDER_UNAVAILABLE',
    )).toEqual({
      result: 'failed',
      intentId: 'intent-1',
      reasonCode: 'PROVIDER_UNAVAILABLE',
    })
    expect(parseIdentityLinkCallback(
      '?identityLink=failed&intentId=intent-1&reasonCode=UNKNOWN_UPPERCASE_CODE',
    )).toEqual({
      result: 'failed',
      intentId: 'intent-1',
    })
  })

  it('resumes failed or reauthenticated intents but not completed links', () => {
    expect(resumableIdentityLinkIntentId({
      result: 'failed',
      intentId: 'intent-1',
    })).toBe('intent-1')
    expect(resumableIdentityLinkIntentId({
      result: 'reauthenticated',
      intentId: 'intent-2',
    })).toBe('intent-2')
    expect(resumableIdentityLinkIntentId({
      result: 'linked',
      intentId: 'intent-3',
    })).toBeUndefined()
  })
})

describe('IdentityLinkManager', () => {
  it('renders local, linked, and available login methods', () => {
    const html = renderToStaticMarkup(<IdentityLinkManager />)

    expect(html).toContain('security.identityLinks.localPassword')
    expect(html).toContain('GitHub')
    expect(html).toContain('Company OIDC')
    expect(html).toContain('security.identityLinks.remove')
    expect(html).toContain('security.identityLinks.add')
  })

  it('disables removal when the binding is the final login method', () => {
    accountState = {
      localPasswordEnabled: false,
      linkedProviders: [{
        bindingId: 42,
        providerCode: 'github',
        displayName: 'GitHub',
        methodTypes: ['OAUTH_REDIRECT'],
        usable: true,
        canUnlink: false,
      }],
      availableProviders: [],
    }

    const html = renderToStaticMarkup(<IdentityLinkManager />)

    expect(html).toContain('security.identityLinks.finalMethodHint')
    expect(html).toMatch(/<button[^>]*disabled/)
  })

  it('shows the browser-link success result after callback', () => {
    vi.stubGlobal('window', {
      location: {
        search: '?identityLink=linked&intentId=intent-1',
        assign: vi.fn(),
      },
    })

    const html = renderToStaticMarkup(<IdentityLinkManager />)

    expect(html).toContain('security.identityLinks.linkSuccess')
    expect(html).not.toContain('security.identityLinks.dialogTitle')
  })

  it('reopens a failed browser flow with its resumable intent', () => {
    vi.stubGlobal('window', {
      location: {
        search: '?identityLink=failed&intentId=intent-1',
        assign: vi.fn(),
      },
    })

    const html = renderToStaticMarkup(<IdentityLinkManager />)

    expect(html).toContain('security.identityLinks.browserFailed')
  })

  it('shows a stable browser failure reason when provided', () => {
    vi.stubGlobal('window', {
      location: {
        search: '?identityLink=failed&intentId=intent-1&reasonCode=PROVIDER_UNAVAILABLE',
        assign: vi.fn(),
      },
    })

    const html = renderToStaticMarkup(<IdentityLinkManager />)

    expect(html).toContain('security.identityLinks.providerUnavailable')
  })
})
