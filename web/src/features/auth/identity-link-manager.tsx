import { useState } from 'react'
import { AlertTriangle, KeyRound, Link2, Loader2, ShieldCheck, Unlink } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { ApiError, buildApiUrl } from '@/api/client'
import type {
  IdentityLinkBinding,
  IdentityLinkCredentialRequest,
  IdentityLinkIntent,
  IdentityLinkProvider,
} from '@/api/types'
import { truncateErrorMessage } from '@/shared/lib/error-display'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import {
  useIdentityLinkAccountState,
  useIdentityLinkActions,
  useIdentityLinkIntent,
} from './use-identity-links'

interface IdentityLinkCallback {
  result?: 'reauthenticated' | 'linked' | 'failed'
  intentId?: string
  reasonCode?: string
}

const identityLinkFailureCodes = new Set([
  'INTENT_NOT_FOUND',
  'REAUTHENTICATION_REQUIRED',
  'SESSION_MISMATCH',
  'INTENT_EXPIRED',
  'ALREADY_CONSUMED',
  'ACTIVE_INTENT_EXISTS',
  'ACCOUNT_NOT_ELIGIBLE',
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_AUTHENTICATION_FAILED',
  'ALREADY_LINKED',
  'IDENTITY_IN_USE',
  'FINAL_LOGIN_METHOD',
  'INVALID_OPERATION',
])

export function parseIdentityLinkCallback(search: string): IdentityLinkCallback {
  const params = new URLSearchParams(search)
  const result = params.get('identityLink')
  const intentId = params.get('intentId') ?? undefined
  const rawReasonCode = params.get('reasonCode')
  const reasonCode = rawReasonCode
    && identityLinkFailureCodes.has(rawReasonCode)
    ? rawReasonCode
    : undefined
  if (
    result !== 'reauthenticated'
    && result !== 'linked'
    && result !== 'failed'
  ) {
    return {}
  }
  return { result, intentId, ...(reasonCode ? { reasonCode } : {}) }
}

export function resumableIdentityLinkIntentId(
  callback: IdentityLinkCallback,
): string | undefined {
  return callback.result === 'reauthenticated' || callback.result === 'failed'
    ? callback.intentId
    : undefined
}

function currentIdentityLinkCallback(): IdentityLinkCallback {
  return typeof window === 'undefined'
    ? {}
    : parseIdentityLinkCallback(window.location.search)
}

function browserFailureMessageKey(
  reasonCode?: string,
): string {
  switch (reasonCode) {
    case 'INTENT_EXPIRED':
    case 'ALREADY_CONSUMED':
    case 'SESSION_MISMATCH':
      return 'security.identityLinks.intentUnavailable'
    case 'PROVIDER_UNAVAILABLE':
      return 'security.identityLinks.providerUnavailable'
    case 'FINAL_LOGIN_METHOD':
      return 'security.identityLinks.finalMethodHint'
    default:
      return 'security.identityLinks.browserFailed'
  }
}

function errorMessage(error: unknown, fallback: string) {
  return truncateErrorMessage(
    error instanceof Error ? error.message : fallback,
  ) ?? fallback
}

function hasMethod(
  provider: IdentityLinkBinding | IdentityLinkProvider,
  method: 'OAUTH_REDIRECT' | 'DIRECT_PASSWORD',
) {
  return provider.methodTypes.includes(method)
}

function CredentialFields({
  prefix,
  value,
  disabled,
  onChange,
}: {
  prefix: string
  value: IdentityLinkCredentialRequest
  disabled: boolean
  onChange: (next: IdentityLinkCredentialRequest) => void
}) {
  const { t } = useTranslation()
  return (
    <>
      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor={`${prefix}-username`}>
          {t('security.identityLinks.username')}
        </label>
        <Input
          id={`${prefix}-username`}
          autoComplete="username"
          value={value.username}
          disabled={disabled}
          onChange={(event) => onChange({
            ...value,
            username: event.target.value,
          })}
        />
      </div>
      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor={`${prefix}-password`}>
          {t('security.identityLinks.password')}
        </label>
        <Input
          id={`${prefix}-password`}
          type="password"
          autoComplete="current-password"
          value={value.password}
          disabled={disabled}
          onChange={(event) => onChange({
            ...value,
            password: event.target.value,
          })}
        />
      </div>
    </>
  )
}

export function IdentityLinkManager() {
  const { t } = useTranslation()
  const callback = currentIdentityLinkCallback()
  const resumableIntentId = resumableIdentityLinkIntentId(callback)
  const [activeIntentId, setActiveIntentId] = useState<string | undefined>(
    resumableIntentId,
  )
  const [dialogOpen, setDialogOpen] = useState(!!resumableIntentId)
  const [localPassword, setLocalPassword] = useState('')
  const [credentialProviderCode, setCredentialProviderCode] = useState<
    string | undefined
  >()
  const [credentials, setCredentials] = useState<IdentityLinkCredentialRequest>({
    username: '',
    password: '',
  })
  const [flowError, setFlowError] = useState(
    callback.result === 'failed'
      ? t(browserFailureMessageKey(callback.reasonCode))
      : '',
  )
  const accountQuery = useIdentityLinkAccountState()
  const intentQuery = useIdentityLinkIntent(activeIntentId)
  const actions = useIdentityLinkActions()
  const account = accountQuery.data
  const intent = intentQuery.data

  const isPending = Object.values(actions).some(
    (mutation) => mutation.isPending,
  )

  function resetFlowFields() {
    setLocalPassword('')
    setCredentialProviderCode(undefined)
    setCredentials({ username: '', password: '' })
    setFlowError('')
  }

  function openIntent(nextIntent: IdentityLinkIntent) {
    resetFlowFields()
    setActiveIntentId(nextIntent.id)
    setDialogOpen(true)
  }

  async function startLink(provider: IdentityLinkProvider) {
    try {
      openIntent(await actions.createLink.mutateAsync(provider.providerCode))
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.defaultError'),
      ))
    }
  }

  async function startUnlink(binding: IdentityLinkBinding) {
    try {
      openIntent(await actions.createUnlink.mutateAsync(binding.bindingId))
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.defaultError'),
      ))
    }
  }

  async function cancelActiveIntent() {
    if (!activeIntentId) {
      setDialogOpen(false)
      return
    }
    if (
      intentQuery.error instanceof ApiError
      && [403, 404, 409, 410].includes(intentQuery.error.status)
    ) {
      setDialogOpen(false)
      setActiveIntentId(undefined)
      resetFlowFields()
      return
    }
    try {
      await actions.cancel.mutateAsync(activeIntentId)
      setDialogOpen(false)
      setActiveIntentId(undefined)
      resetFlowFields()
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.defaultError'),
      ))
    }
  }

  function handleDialogOpenChange(open: boolean) {
    if (open) {
      setDialogOpen(true)
      return
    }
    if (intent?.status === 'COMPLETED' || intent?.status === 'CANCELLED') {
      setDialogOpen(false)
      setActiveIntentId(undefined)
      resetFlowFields()
      return
    }
    void cancelActiveIntent()
  }

  async function reauthenticateLocal(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!activeIntentId || !localPassword) {
      setFlowError(t('security.identityLinks.passwordRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.reauthenticateLocal.mutateAsync({
        intentId: activeIntentId,
        password: localPassword,
      })
      setLocalPassword('')
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.reauthenticationFailed'),
      ))
    }
  }

  async function reauthenticateCredential(
    event: React.FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()
    if (
      !activeIntentId
      || !credentialProviderCode
      || !credentials.username.trim()
      || !credentials.password
    ) {
      setFlowError(t('security.identityLinks.credentialsRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.reauthenticateCredential.mutateAsync({
        intentId: activeIntentId,
        providerCode: credentialProviderCode,
        credentials: {
          username: credentials.username.trim(),
          password: credentials.password,
        },
      })
      setCredentials({ username: '', password: '' })
      setCredentialProviderCode(undefined)
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.reauthenticationFailed'),
      ))
    }
  }

  async function redirectToBrowserReauthentication(providerCode: string) {
    if (!activeIntentId) return
    setFlowError('')
    try {
      const actionUrl =
        await actions.prepareBrowserReauthentication.mutateAsync({
          intentId: activeIntentId,
          providerCode,
        })
      window.location.assign(buildApiUrl(actionUrl))
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.reauthenticationFailed'),
      ))
    }
  }

  async function redirectToBrowserLink() {
    if (!activeIntentId) return
    setFlowError('')
    try {
      const actionUrl = await actions.prepareBrowserLink.mutateAsync(
        activeIntentId,
      )
      window.location.assign(buildApiUrl(actionUrl))
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.linkFailed'),
      ))
    }
  }

  async function linkCredential(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (
      !activeIntentId
      || !credentials.username.trim()
      || !credentials.password
    ) {
      setFlowError(t('security.identityLinks.credentialsRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.linkCredential.mutateAsync({
        intentId: activeIntentId,
        credentials: {
          username: credentials.username.trim(),
          password: credentials.password,
        },
      })
      setDialogOpen(false)
      setActiveIntentId(undefined)
      resetFlowFields()
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.linkFailed'),
      ))
    }
  }

  async function completeUnlink() {
    if (!activeIntentId) return
    setFlowError('')
    try {
      await actions.completeUnlink.mutateAsync(activeIntentId)
      setDialogOpen(false)
      setActiveIntentId(undefined)
      resetFlowFields()
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('security.identityLinks.unlinkFailed'),
      ))
    }
  }

  const linkedProviders = account?.linkedProviders ?? []
  const targetProvider = intent?.operation === 'LINK'
    ? account?.availableProviders.find(
      (provider) => provider.providerCode === intent.providerCode,
    )
    : undefined
  const targetBinding = intent?.operation === 'UNLINK'
    ? linkedProviders.find(
      (binding) => binding.bindingId === intent.targetBindingId,
    )
    : undefined
  const browserReauthenticationProviders = linkedProviders.filter(
    (provider) => provider.usable && hasMethod(provider, 'OAUTH_REDIRECT'),
  )
  const credentialReauthenticationProviders = linkedProviders.filter(
    (provider) => provider.usable && hasMethod(provider, 'DIRECT_PASSWORD'),
  )
  const hasFreshReauthenticationMethod =
    account?.localPasswordEnabled
    || browserReauthenticationProviders.length > 0
    || credentialReauthenticationProviders.length > 0

  return (
    <>
      <Card className="glass-strong">
        <CardHeader>
          <CardTitle>{t('security.identityLinks.title')}</CardTitle>
          <CardDescription>
            {t('security.identityLinks.subtitle')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {callback.result === 'linked' ? (
            <div className="rounded-lg border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-800">
              {t('security.identityLinks.linkSuccess')}
            </div>
          ) : null}
          {callback.result === 'failed' ? (
            <div className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-700">
              {t(browserFailureMessageKey(callback.reasonCode))}
            </div>
          ) : null}
          {flowError && !dialogOpen ? (
            <div className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-700">
              {flowError}
            </div>
          ) : null}

          {accountQuery.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              {t('security.identityLinks.loading')}
            </div>
          ) : accountQuery.error ? (
            <p className="text-sm text-red-600">
              {errorMessage(
                accountQuery.error,
                t('security.identityLinks.defaultError'),
              )}
            </p>
          ) : (
            <>
              <section className="space-y-3" aria-labelledby="linked-login-methods">
                <h3 id="linked-login-methods" className="text-sm font-semibold">
                  {t('security.identityLinks.linkedTitle')}
                </h3>
                {account?.localPasswordEnabled ? (
                  <div className="flex items-center justify-between gap-4 rounded-xl border border-border/70 p-4">
                    <div className="flex min-w-0 items-center gap-3">
                      <KeyRound className="h-5 w-5 shrink-0 text-primary" />
                      <div>
                        <p className="font-medium">
                          {t('security.identityLinks.localPassword')}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {t('security.identityLinks.localPasswordDescription')}
                        </p>
                      </div>
                    </div>
                    <span className="rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-800">
                      {t('security.identityLinks.active')}
                    </span>
                  </div>
                ) : null}
                {linkedProviders.map((provider) => (
                  <div
                    key={provider.bindingId}
                    className="flex items-center justify-between gap-4 rounded-xl border border-border/70 p-4"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <ShieldCheck className="h-5 w-5 shrink-0 text-primary" />
                      <div className="min-w-0">
                        <p className="truncate font-medium">
                          {provider.displayName}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {provider.usable
                            ? t('security.identityLinks.externalLogin')
                            : t('security.identityLinks.providerUnavailable')}
                        </p>
                      </div>
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={!provider.canUnlink || isPending}
                      title={!provider.canUnlink
                        ? t('security.identityLinks.finalMethodHint')
                        : undefined}
                      onClick={() => void startUnlink(provider)}
                    >
                      <Unlink className="mr-2 h-3.5 w-3.5" />
                      {t('security.identityLinks.remove')}
                    </Button>
                  </div>
                ))}
                {!account?.localPasswordEnabled && linkedProviders.length === 0 ? (
                  <p className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
                    {t('security.identityLinks.noLinkedMethods')}
                  </p>
                ) : null}
              </section>

              <section className="space-y-3" aria-labelledby="available-login-methods">
                <h3 id="available-login-methods" className="text-sm font-semibold">
                  {t('security.identityLinks.availableTitle')}
                </h3>
                {(account?.availableProviders ?? []).map((provider) => (
                  <div
                    key={provider.providerCode}
                    className="flex items-center justify-between gap-4 rounded-xl border border-border/70 p-4"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <Link2 className="h-5 w-5 shrink-0 text-primary" />
                      <div>
                        <p className="font-medium">{provider.displayName}</p>
                        <p className="text-sm text-muted-foreground">
                          {t('security.identityLinks.availableDescription')}
                        </p>
                      </div>
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      disabled={isPending}
                      onClick={() => void startLink(provider)}
                    >
                      {t('security.identityLinks.add')}
                    </Button>
                  </div>
                ))}
                {account?.availableProviders.length === 0 ? (
                  <p className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
                    {t('security.identityLinks.noAvailableMethods')}
                  </p>
                ) : null}
              </section>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={handleDialogOpenChange}>
        <DialogContent aria-label={t('security.identityLinks.dialogTitle')}>
          <DialogHeader>
            <DialogTitle>{t('security.identityLinks.dialogTitle')}</DialogTitle>
            <DialogDescription>
              {intent?.operation === 'UNLINK'
                ? t('security.identityLinks.unlinkDialogDescription', {
                  name: targetBinding?.displayName ?? intent.providerCode,
                })
                : t('security.identityLinks.linkDialogDescription', {
                  name: targetProvider?.displayName ?? intent?.providerCode ?? '',
                })}
            </DialogDescription>
          </DialogHeader>

          {intentQuery.isLoading ? (
            <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              {t('security.identityLinks.loadingIntent')}
            </div>
          ) : intentQuery.error ? (
            <p className="text-sm text-red-600">
              {errorMessage(
                intentQuery.error,
                t('security.identityLinks.defaultError'),
              )}
            </p>
          ) : null}

          {intent?.status === 'PENDING_REAUTHENTICATION' ? (
            <div className="space-y-5">
              <div className="rounded-lg border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
                {t('security.identityLinks.reauthenticationDescription')}
              </div>

              {account?.localPasswordEnabled ? (
                <form className="space-y-3" onSubmit={reauthenticateLocal}>
                  <label className="text-sm font-medium" htmlFor="identity-link-local-password">
                    {t('security.identityLinks.localPassword')}
                  </label>
                  <Input
                    id="identity-link-local-password"
                    type="password"
                    autoComplete="current-password"
                    value={localPassword}
                    disabled={isPending}
                    onChange={(event) => setLocalPassword(event.target.value)}
                  />
                  <Button type="submit" size="sm" disabled={isPending}>
                    {t('security.identityLinks.verifyPassword')}
                  </Button>
                </form>
              ) : null}

              {browserReauthenticationProviders.length > 0 ? (
                <div className="space-y-2">
                  <p className="text-sm font-medium">
                    {t('security.identityLinks.verifyWithProvider')}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {browserReauthenticationProviders.map((provider) => (
                      <Button
                        key={provider.providerCode}
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={isPending}
                        onClick={() => void redirectToBrowserReauthentication(
                          provider.providerCode,
                        )}
                      >
                        {provider.displayName}
                      </Button>
                    ))}
                  </div>
                </div>
              ) : null}

              {credentialReauthenticationProviders.length > 0 ? (
                <div className="space-y-3">
                  <p className="text-sm font-medium">
                    {t('security.identityLinks.verifyWithCredentials')}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {credentialReauthenticationProviders.map((provider) => (
                      <Button
                        key={provider.providerCode}
                        type="button"
                        size="sm"
                        variant={credentialProviderCode === provider.providerCode
                          ? 'secondary'
                          : 'outline'}
                        disabled={isPending}
                        onClick={() => {
                          setCredentialProviderCode(provider.providerCode)
                          setCredentials({ username: '', password: '' })
                        }}
                      >
                        {provider.displayName}
                      </Button>
                    ))}
                  </div>
                  {credentialProviderCode ? (
                    <form className="space-y-3" onSubmit={reauthenticateCredential}>
                      <CredentialFields
                        prefix="identity-link-reauth"
                        value={credentials}
                        disabled={isPending}
                        onChange={setCredentials}
                      />
                      <Button type="submit" size="sm" disabled={isPending}>
                        {t('security.identityLinks.verifyCredentials')}
                      </Button>
                    </form>
                  ) : null}
                </div>
              ) : null}

              {!hasFreshReauthenticationMethod ? (
                <div className="flex gap-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  {t('security.identityLinks.noReauthenticationMethod')}
                </div>
              ) : null}
            </div>
          ) : null}

          {intent?.status === 'READY' && intent.operation === 'LINK' ? (
            <div className="space-y-5">
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">
                {t('security.identityLinks.reauthenticated')}
              </div>
              {targetProvider && hasMethod(targetProvider, 'OAUTH_REDIRECT') ? (
                <Button
                  type="button"
                  className="w-full"
                  disabled={isPending}
                  onClick={() => void redirectToBrowserLink()}
                >
                  {t('security.identityLinks.continueWithProvider', {
                    name: targetProvider.displayName,
                  })}
                </Button>
              ) : null}
              {targetProvider && hasMethod(targetProvider, 'DIRECT_PASSWORD') ? (
                <form className="space-y-3" onSubmit={linkCredential}>
                  <CredentialFields
                    prefix="identity-link-target"
                    value={credentials}
                    disabled={isPending}
                    onChange={setCredentials}
                  />
                  <Button type="submit" className="w-full" disabled={isPending}>
                    {t('security.identityLinks.linkProvider', {
                      name: targetProvider.displayName,
                    })}
                  </Button>
                </form>
              ) : null}
              {!targetProvider ? (
                <p className="text-sm text-red-600">
                  {t('security.identityLinks.providerUnavailable')}
                </p>
              ) : null}
            </div>
          ) : null}

          {intent?.status === 'READY' && intent.operation === 'UNLINK' ? (
            <div className="space-y-4">
              <div className="flex gap-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                {t('security.identityLinks.unlinkConfirmation', {
                  name: targetBinding?.displayName ?? intent.providerCode,
                })}
              </div>
              <Button
                type="button"
                variant="destructive"
                className="w-full"
                disabled={isPending}
                onClick={() => void completeUnlink()}
              >
                {t('security.identityLinks.confirmRemove')}
              </Button>
            </div>
          ) : null}

          {intent && (
            intent.status === 'EXPIRED'
            || intent.status === 'CANCELLED'
          ) ? (
            <p className="text-sm text-amber-700">
              {t('security.identityLinks.intentUnavailable')}
            </p>
          ) : null}

          {flowError && dialogOpen ? (
            <p className="text-sm text-red-600">{flowError}</p>
          ) : null}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={isPending}
              onClick={() => void cancelActiveIntent()}
            >
              {t('security.identityLinks.cancel')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
