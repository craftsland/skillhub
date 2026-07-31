import { describe, expect, it } from 'vitest'
import * as accountMerge from './use-account-merge'

describe('use-account-merge module exports', () => {
  it('exports the capability, intent, and action hooks', () => {
    expect(accountMerge.useAccountMergeCapabilities).toBeTypeOf('function')
    expect(accountMerge.useAccountMergeIntent).toBeTypeOf('function')
    expect(accountMerge.useAccountMergeActions).toBeTypeOf('function')
  })

  it('uses intent-scoped query keys', () => {
    expect(accountMerge.accountMergeKeys.intent('intent-1')).toEqual([
      'auth',
      'account-merge',
      'intent',
      'intent-1',
    ])
  })
})
