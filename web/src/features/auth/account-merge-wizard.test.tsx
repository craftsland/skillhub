import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  AccountMergeCapabilities,
  AccountMergeIntent,
} from '@/api/types'

let capabilitiesState: {
  data?: AccountMergeCapabilities
  isLoading: boolean
  error: Error | null
}
let intentState: {
  data?: AccountMergeIntent
  isLoading: boolean
  error: Error | null
}

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
  ApiError: class ApiError extends Error {
    status = 409
    reasonCode?: string
  },
  buildApiUrl: (value: string) => value,
}))

vi.mock('./use-account-merge', () => ({
  useAccountMergeCapabilities: () => capabilitiesState,
  useAccountMergeIntent: () => intentState,
  useAccountMergeActions: () => ({
    reauthenticatePrimaryLocal: mutation(),
    reauthenticatePrimaryCredential: mutation(),
    preparePrimaryBrowser: mutation(),
    createIntent: mutation(),
    authenticateSecondaryLocal: mutation(),
    authenticateSecondaryCredential: mutation(),
    prepareSecondaryBrowser: mutation(),
    preview: mutation(),
    confirm: mutation(),
    cancel: mutation(),
  }),
}))

import {
  AccountMergeWizard,
  accountMergeFailureMessageKey,
  parseAccountMergeCallback,
} from './account-merge-wizard'

beforeEach(() => {
  vi.stubGlobal('window', {
    location: {
      search: '',
      assign: vi.fn(),
    },
    history: {
      replaceState: vi.fn(),
    },
  })
  capabilitiesState = {
    data: {
      enabled: true,
      primaryMethods: [{
        providerCode: 'local',
        displayName: 'Local password',
        methodType: 'LOCAL_PASSWORD',
      }],
      secondaryMethods: [{
        providerCode: 'github',
        displayName: 'GitHub',
        methodType: 'OAUTH_REDIRECT',
      }],
    },
    isLoading: false,
    error: null,
  }
  intentState = {
    isLoading: false,
    error: null,
  }
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('parseAccountMergeCallback', () => {
  it('accepts only supported results, UUIDs, phases, and reason codes', () => {
    expect(parseAccountMergeCallback(
      '?accountMerge=secondaryProved'
      + '&intentId=8f2bb16c-6e11-4e48-a7a4-6be46ecb0902',
    )).toEqual({
      result: 'secondaryProved',
      intentId: '8f2bb16c-6e11-4e48-a7a4-6be46ecb0902',
    })
    expect(parseAccountMergeCallback(
      '?accountMerge=failed'
      + '&phase=SECONDARY_AUTHENTICATION'
      + '&reasonCode=MERGE_PROVIDER_UNAVAILABLE',
    )).toEqual({
      result: 'failed',
      phase: 'SECONDARY_AUTHENTICATION',
      reasonCode: 'MERGE_PROVIDER_UNAVAILABLE',
    })
    expect(parseAccountMergeCallback(
      '?accountMerge=failed&intentId=not-a-uuid&reasonCode=UNKNOWN',
    )).toEqual({ result: 'failed' })
    expect(parseAccountMergeCallback(
      '?accountMerge=unexpected',
    )).toEqual({})
  })

  it('maps stable failures without exposing raw callback values', () => {
    expect(accountMergeFailureMessageKey(
      'MERGE_PREVIEW_STALE',
    )).toBe('accounts.errors.previewStale')
    expect(accountMergeFailureMessageKey(
      'UNTRUSTED_VALUE',
    )).toBe('accounts.errors.default')
  })
})

describe('AccountMergeWizard', () => {
  it('renders the fail-closed unavailable state from capabilities', () => {
    capabilitiesState.data = {
      enabled: false,
      primaryMethods: [],
      secondaryMethods: [],
    }

    const html = renderToStaticMarkup(<AccountMergeWizard />)

    expect(html).toContain('accounts.unavailableTitle')
    expect(html).not.toContain('account-merge-primary-password')
  })

  it('renders only methods advertised for the primary account', () => {
    const html = renderToStaticMarkup(<AccountMergeWizard />)

    expect(html).toContain('accounts.primary.title')
    expect(html).toContain('account-merge-primary-password')
    expect(html).not.toContain('GitHub')
  })

  it('resumes a secondary-proof intent from a browser callback', () => {
    vi.stubGlobal('window', {
      location: {
        search: '?accountMerge=secondaryProved'
          + '&intentId=8f2bb16c-6e11-4e48-a7a4-6be46ecb0902',
        assign: vi.fn(),
      },
      history: {
        replaceState: vi.fn(),
      },
    })
    intentState.data = {
      id: '8f2bb16c-6e11-4e48-a7a4-6be46ecb0902',
      status: 'READY_FOR_PREVIEW',
      expiresAt: '2026-07-31T08:00:00Z',
      secondaryMethods: [],
    }

    const html = renderToStaticMarkup(<AccountMergeWizard />)

    expect(html).toContain('accounts.secondaryBrowserSuccess')
    expect(html).toContain('accounts.preview.build')
  })
})
