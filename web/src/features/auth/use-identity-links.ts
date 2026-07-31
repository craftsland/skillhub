import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { identityLinkApi } from '@/api/client'
import type {
  IdentityLinkCredentialRequest,
  IdentityLinkIntent,
} from '@/api/types'

export const identityLinkKeys = {
  account: ['auth', 'identity-links'] as const,
  intent: (intentId: string) =>
    ['auth', 'identity-link-intent', intentId] as const,
}

export function useIdentityLinkAccountState() {
  return useQuery({
    queryKey: identityLinkKeys.account,
    queryFn: identityLinkApi.getAccountState,
    staleTime: 15_000,
  })
}

export function useIdentityLinkIntent(intentId?: string) {
  return useQuery({
    queryKey: identityLinkKeys.intent(intentId ?? ''),
    queryFn: () => identityLinkApi.getIntent(intentId ?? ''),
    enabled: !!intentId,
    retry: false,
  })
}

export function useIdentityLinkActions() {
  const queryClient = useQueryClient()

  function cacheIntent(intent: IdentityLinkIntent) {
    queryClient.setQueryData(
      identityLinkKeys.intent(intent.id),
      intent,
    )
  }

  async function refreshAccountState() {
    await queryClient.invalidateQueries({
      queryKey: identityLinkKeys.account,
    })
  }

  const createLink = useMutation({
    mutationFn: identityLinkApi.createLinkIntent,
    onSuccess: cacheIntent,
  })
  const createUnlink = useMutation({
    mutationFn: identityLinkApi.createUnlinkIntent,
    onSuccess: cacheIntent,
  })
  const cancel = useMutation({
    mutationFn: identityLinkApi.cancel,
    onSuccess: cacheIntent,
  })
  const reauthenticateLocal = useMutation({
    mutationFn: ({
      intentId,
      password,
    }: {
      intentId: string
      password: string
    }) => identityLinkApi.reauthenticateLocal(intentId, password),
    onSuccess: cacheIntent,
  })
  const prepareBrowserReauthentication = useMutation({
    mutationFn: ({
      intentId,
      providerCode,
    }: {
      intentId: string
      providerCode: string
    }) => identityLinkApi.prepareBrowserReauthentication(
      intentId,
      providerCode,
    ),
  })
  const reauthenticateCredential = useMutation({
    mutationFn: ({
      intentId,
      providerCode,
      credentials,
    }: {
      intentId: string
      providerCode: string
      credentials: IdentityLinkCredentialRequest
    }) => identityLinkApi.reauthenticateCredential(
      intentId,
      providerCode,
      credentials,
    ),
    onSuccess: cacheIntent,
  })
  const prepareBrowserLink = useMutation({
    mutationFn: identityLinkApi.prepareBrowserLink,
  })
  const linkCredential = useMutation({
    mutationFn: ({
      intentId,
      credentials,
    }: {
      intentId: string
      credentials: IdentityLinkCredentialRequest
    }) => identityLinkApi.linkCredential(intentId, credentials),
    onSuccess: async (intent) => {
      cacheIntent(intent)
      await refreshAccountState()
    },
  })
  const completeUnlink = useMutation({
    mutationFn: identityLinkApi.completeUnlink,
    onSuccess: async (intent) => {
      cacheIntent(intent)
      await refreshAccountState()
    },
  })

  return {
    createLink,
    createUnlink,
    cancel,
    reauthenticateLocal,
    prepareBrowserReauthentication,
    reauthenticateCredential,
    prepareBrowserLink,
    linkCredential,
    completeUnlink,
  }
}
