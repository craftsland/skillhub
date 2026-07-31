import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { accountApi } from '@/api/client'
import type {
  AccountMergeCredentialRequest,
  AccountMergeIntent,
} from '@/api/types'

export const accountMergeKeys = {
  capabilities: ['auth', 'account-merge', 'capabilities'] as const,
  intent: (intentId: string) =>
    ['auth', 'account-merge', 'intent', intentId] as const,
  completion: (intentId: string) =>
    ['auth', 'account-merge', 'completion', intentId] as const,
}

export function useAccountMergeCapabilities() {
  return useQuery({
    queryKey: accountMergeKeys.capabilities,
    queryFn: accountApi.capabilities,
    staleTime: 15_000,
    retry: false,
  })
}

export function useAccountMergeIntent(intentId?: string) {
  return useQuery({
    queryKey: accountMergeKeys.intent(intentId ?? ''),
    queryFn: () => accountApi.getIntent(intentId ?? ''),
    enabled: !!intentId,
    retry: false,
  })
}

export function useAccountMergeActions() {
  const queryClient = useQueryClient()

  function cacheIntent(intent: AccountMergeIntent) {
    queryClient.setQueryData(
      accountMergeKeys.intent(intent.id),
      intent,
    )
  }

  const reauthenticatePrimaryLocal = useMutation({
    mutationFn: accountApi.reauthenticatePrimaryLocal,
  })
  const reauthenticatePrimaryCredential = useMutation({
    mutationFn: ({
      providerCode,
      credentials,
    }: {
      providerCode: string
      credentials: AccountMergeCredentialRequest
    }) => accountApi.reauthenticatePrimaryCredential(
      providerCode,
      credentials,
    ),
  })
  const preparePrimaryBrowser = useMutation({
    mutationFn: accountApi.preparePrimaryBrowser,
  })
  const createIntent = useMutation({
    mutationFn: accountApi.createIntent,
    onSuccess: cacheIntent,
  })
  const authenticateSecondaryLocal = useMutation({
    mutationFn: ({
      intentId,
      credentials,
    }: {
      intentId: string
      credentials: AccountMergeCredentialRequest
    }) => accountApi.authenticateSecondaryLocal(
      intentId,
      credentials,
    ),
    onSuccess: cacheIntent,
  })
  const authenticateSecondaryCredential = useMutation({
    mutationFn: ({
      intentId,
      providerCode,
      credentials,
    }: {
      intentId: string
      providerCode: string
      credentials: AccountMergeCredentialRequest
    }) => accountApi.authenticateSecondaryCredential(
      intentId,
      providerCode,
      credentials,
    ),
    onSuccess: cacheIntent,
  })
  const prepareSecondaryBrowser = useMutation({
    mutationFn: ({
      intentId,
      providerCode,
    }: {
      intentId: string
      providerCode: string
    }) => accountApi.prepareSecondaryBrowser(
      intentId,
      providerCode,
    ),
  })
  const preview = useMutation({
    mutationFn: accountApi.preview,
    onSuccess: (result) => {
      queryClient.setQueryData<AccountMergeIntent>(
        accountMergeKeys.intent(result.intentId),
        (current) => current
          ? { ...current, status: result.status }
          : current,
      )
    },
  })
  const confirm = useMutation({
    mutationFn: ({
      intentId,
      previewVersion,
    }: {
      intentId: string
      previewVersion: number
    }) => accountApi.confirm(intentId, previewVersion),
    onSuccess: async (completion) => {
      queryClient.setQueryData(
        accountMergeKeys.completion(completion.intentId),
        completion,
      )
      queryClient.setQueryData<AccountMergeIntent>(
        accountMergeKeys.intent(completion.intentId),
        (current) => current
          ? { ...current, status: completion.status }
          : current,
      )
      await queryClient.invalidateQueries()
    },
  })
  const cancel = useMutation({
    mutationFn: accountApi.cancel,
    onSuccess: (intent) => {
      cacheIntent(intent)
    },
  })

  return {
    reauthenticatePrimaryLocal,
    reauthenticatePrimaryCredential,
    preparePrimaryBrowser,
    createIntent,
    authenticateSecondaryLocal,
    authenticateSecondaryCredential,
    prepareSecondaryBrowser,
    preview,
    confirm,
    cancel,
  }
}
