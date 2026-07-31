import { useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  KeyRound,
  Loader2,
  ShieldCheck,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  ApiError,
  buildApiUrl,
} from '@/api/client'
import type {
  AccountMergeAuthenticationMethod,
  AccountMergeCredentialRequest,
  AccountMergePreview,
} from '@/api/types'
import { truncateErrorMessage } from '@/shared/lib/error-display'
import { cn } from '@/shared/lib/utils'
import { Button } from '@/shared/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import {
  useAccountMergeActions,
  useAccountMergeCapabilities,
  useAccountMergeIntent,
} from './use-account-merge'

interface AccountMergeCallback {
  result?: 'primaryProved' | 'secondaryProved' | 'failed'
  intentId?: string
  phase?: 'PRIMARY_REAUTHENTICATION' | 'SECONDARY_AUTHENTICATION' | 'UNKNOWN'
  reasonCode?: string
}

const accountMergeFailureCodes = new Set([
  'ACCOUNT_MERGE_UNAVAILABLE',
  'MERGE_INTENT_NOT_FOUND',
  'MERGE_REAUTH_REQUIRED',
  'MERGE_PROVIDER_AUTHENTICATION_FAILED',
  'MERGE_PROVIDER_UNAVAILABLE',
  'MERGE_SESSION_MISMATCH',
  'MERGE_PROOF_EXPIRED',
  'MERGE_CONFLICT',
  'MERGE_PREVIEW_STALE',
  'MERGE_ALREADY_CONSUMED',
  'MERGE_ACCOUNT_NOT_ELIGIBLE',
])

const accountMergeCallbackPhases = new Set([
  'PRIMARY_REAUTHENTICATION',
  'SECONDARY_AUTHENTICATION',
  'UNKNOWN',
])

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function parseAccountMergeCallback(
  search: string,
): AccountMergeCallback {
  const params = new URLSearchParams(search)
  const result = params.get('accountMerge')
  if (
    result !== 'primaryProved'
    && result !== 'secondaryProved'
    && result !== 'failed'
  ) {
    return {}
  }
  const rawIntentId = params.get('intentId')
  const intentId = rawIntentId && uuidPattern.test(rawIntentId)
    ? rawIntentId
    : undefined
  const rawPhase = params.get('phase')
  const phase = rawPhase && accountMergeCallbackPhases.has(rawPhase)
    ? rawPhase as AccountMergeCallback['phase']
    : undefined
  const rawReasonCode = params.get('reasonCode')
  const reasonCode = rawReasonCode
    && accountMergeFailureCodes.has(rawReasonCode)
    ? rawReasonCode
    : undefined
  return {
    result,
    ...(intentId ? { intentId } : {}),
    ...(phase ? { phase } : {}),
    ...(reasonCode ? { reasonCode } : {}),
  }
}

export function accountMergeFailureMessageKey(
  reasonCode?: string,
): string {
  switch (reasonCode) {
    case 'ACCOUNT_MERGE_UNAVAILABLE':
      return 'accounts.errors.unavailable'
    case 'MERGE_INTENT_NOT_FOUND':
    case 'MERGE_SESSION_MISMATCH':
    case 'MERGE_PROOF_EXPIRED':
    case 'MERGE_ALREADY_CONSUMED':
      return 'accounts.errors.intentUnavailable'
    case 'MERGE_REAUTH_REQUIRED':
      return 'accounts.errors.authenticationFailed'
    case 'MERGE_PROVIDER_AUTHENTICATION_FAILED':
      return 'accounts.errors.providerAuthenticationFailed'
    case 'MERGE_PROVIDER_UNAVAILABLE':
      return 'accounts.errors.providerUnavailable'
    case 'MERGE_CONFLICT':
      return 'accounts.errors.conflict'
    case 'MERGE_PREVIEW_STALE':
      return 'accounts.errors.previewStale'
    case 'MERGE_ACCOUNT_NOT_ELIGIBLE':
      return 'accounts.errors.accountNotEligible'
    default:
      return 'accounts.errors.default'
  }
}

function currentCallback(): AccountMergeCallback {
  return typeof window === 'undefined'
    ? {}
    : parseAccountMergeCallback(window.location.search)
}

function currentIntentId(): string | undefined {
  if (typeof window === 'undefined') return undefined
  const value = new URLSearchParams(window.location.search)
    .get('intentId')
  return value && uuidPattern.test(value) ? value : undefined
}

function replaceIntentLocation(intentId?: string) {
  if (typeof window === 'undefined' || !window.history) return
  const path = intentId
    ? `/settings/accounts?intentId=${encodeURIComponent(intentId)}`
    : '/settings/accounts'
  window.history.replaceState({}, '', path)
}

function uniqueMethods(
  methods: AccountMergeAuthenticationMethod[],
  acceptedTypes: Set<string>,
) {
  const result = new Map<string, AccountMergeAuthenticationMethod>()
  for (const method of methods) {
    if (
      acceptedTypes.has(method.methodType)
      && !result.has(method.providerCode)
    ) {
      result.set(method.providerCode, method)
    }
  }
  return [...result.values()]
}

function errorMessage(
  error: unknown,
  fallback: string,
  translate: (key: string) => string,
) {
  if (error instanceof ApiError && error.reasonCode) {
    return translate(accountMergeFailureMessageKey(error.reasonCode))
  }
  return truncateErrorMessage(
    error instanceof Error ? error.message : fallback,
  ) ?? fallback
}

function CredentialFields({
  prefix,
  value,
  disabled,
  onChange,
}: {
  prefix: string
  value: AccountMergeCredentialRequest
  disabled: boolean
  onChange: (next: AccountMergeCredentialRequest) => void
}) {
  const { t } = useTranslation()
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-2">
        <label className="text-sm font-medium" htmlFor={`${prefix}-username`}>
          {t('accounts.authentication.username')}
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
          {t('accounts.authentication.password')}
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
    </div>
  )
}

function PreviewSection({ preview }: { preview: AccountMergePreview }) {
  const { t } = useTranslation()
  const social = preview.social
  const notifications = preview.notifications

  return (
    <div className="space-y-5">
      <div className={cn(
        'rounded-xl border p-4',
        preview.confirmable
          ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-200'
          : 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/30 dark:text-red-200',
      )}>
        <div className="flex items-start gap-3">
          {preview.confirmable
            ? <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" />
            : <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />}
          <div>
            <p className="font-medium">
              {preview.confirmable
                ? t('accounts.preview.readyTitle')
                : t('accounts.preview.blockedTitle')}
            </p>
            <p className="mt-1 text-sm">
              {preview.confirmable
                ? t('accounts.preview.readyDescription')
                : t('accounts.preview.blockedDescription')}
            </p>
          </div>
        </div>
      </div>

      {social.discardedRatings.length > 0 ? (
        <section className="space-y-2">
          <h4 className="text-sm font-semibold">
            {t('accounts.preview.discardedRatings')}
          </h4>
          <ul className="space-y-1 text-sm text-muted-foreground">
            {social.discardedRatings.map((rating) => (
              <li key={rating.skillId}>
                {t('accounts.preview.discardedRating', {
                  skillId: rating.skillId,
                  score: rating.score,
                })}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2">
        <PreviewValue
          label={t('accounts.preview.identityProviders')}
          value={preview.identityProviders.length > 0
            ? preview.identityProviders.join(', ')
            : t('accounts.preview.none')}
        />
        <PreviewValue
          label={t('accounts.preview.localCredential')}
          value={t(
            `accounts.preview.localCredentialActions.${preview.localCredentialAction}`,
            { defaultValue: preview.localCredentialAction },
          )}
        />
        <PreviewValue
          label={t('accounts.preview.skills')}
          value={String(preview.skillOwnershipCount)}
        />
        <PreviewValue
          label={t('accounts.preview.tokens')}
          value={String(preview.apiTokensToRevoke.length)}
        />
      </div>

      {preview.namespaceChanges.length > 0 ? (
        <section className="space-y-2">
          <h4 className="text-sm font-semibold">
            {t('accounts.preview.namespaces')}
          </h4>
          <div className="space-y-2">
            {preview.namespaceChanges.map((change) => (
              <div
                key={change.namespaceId}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/70 p-3 text-sm"
              >
                <span className="font-medium">@{change.namespaceSlug}</span>
                <span className={change.blocked ? 'text-red-600' : 'text-muted-foreground'}>
                  {change.primaryRole ?? t('accounts.preview.none')}
                  {' + '}
                  {change.secondaryRole ?? t('accounts.preview.none')}
                  {' → '}
                  {change.resultingRole ?? t('accounts.preview.none')}
                </span>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {preview.apiTokensToRevoke.length > 0 ? (
        <section className="space-y-2">
          <h4 className="text-sm font-semibold">
            {t('accounts.preview.tokensToRevoke')}
          </h4>
          <ul className="space-y-1 text-sm text-muted-foreground">
            {preview.apiTokensToRevoke.map((token) => (
              <li key={`${token.name}:${token.prefix}`}>
                {token.name} ({token.prefix}…)
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2">
        <PreviewValue
          label={t('accounts.preview.social')}
          value={t('accounts.preview.socialSummary', {
            stars: social.starsMoved,
            ratings: social.ratingsMoved,
            subscriptions: social.subscriptionsMoved,
            duplicates:
              social.duplicateStarsDiscarded
              + social.duplicateRatingsDiscarded
              + social.duplicateSubscriptionsDiscarded,
          })}
        />
        <PreviewValue
          label={t('accounts.preview.notifications')}
          value={t('accounts.preview.notificationSummary', {
            notifications: notifications.notificationsMoved,
            preferences: notifications.preferencesMoved,
            governance: notifications.governanceNotificationsMoved,
            duplicates: notifications.duplicatePreferencesDiscarded,
          })}
        />
      </div>

      {preview.blockedPlatformRoles.length > 0 ? (
        <ConflictList
          title={t('accounts.preview.blockedRoles')}
          items={preview.blockedPlatformRoles}
        />
      ) : null}
      {preview.conflicts.length > 0 ? (
        <ConflictList
          title={t('accounts.preview.conflicts')}
          items={preview.conflicts.map(
            (conflict) => t('accounts.preview.conflictItem', {
              resource: conflict.resource,
              action: t(
                `accounts.preview.conflictActions.${conflict.suggestedAction}`,
                { defaultValue: conflict.suggestedAction },
              ),
            }),
          )}
        />
      ) : null}
    </div>
  )
}

function PreviewValue({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="rounded-lg border border-border/70 p-3">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 break-words text-sm">{value}</p>
    </div>
  )
}

function ConflictList({
  title,
  items,
}: {
  title: string
  items: string[]
}) {
  return (
    <section className="rounded-lg border border-red-300 bg-red-50 p-3 text-red-800 dark:border-red-900 dark:bg-red-950/30 dark:text-red-200">
      <h4 className="text-sm font-semibold">{title}</h4>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  )
}

export function AccountMergeWizard() {
  const { t } = useTranslation()
  const [callback] = useState(currentCallback)
  const [activeIntentId, setActiveIntentId] = useState<string | undefined>(
    callback.intentId ?? currentIntentId(),
  )
  const [primaryPassword, setPrimaryPassword] = useState('')
  const [primaryCredentials, setPrimaryCredentials] =
    useState<AccountMergeCredentialRequest>({
      username: '',
      password: '',
    })
  const [secondaryCredentials, setSecondaryCredentials] =
    useState<AccountMergeCredentialRequest>({
      username: '',
      password: '',
    })
  const [acknowledged, setAcknowledged] = useState(false)
  const [completed, setCompleted] = useState(false)
  const [flowError, setFlowError] = useState(
    callback.result === 'failed'
      ? t(accountMergeFailureMessageKey(callback.reasonCode))
      : '',
  )

  const capabilitiesQuery = useAccountMergeCapabilities()
  const intentQuery = useAccountMergeIntent(activeIntentId)
  const actions = useAccountMergeActions()
  const preview = actions.preview.data
  const capabilities = capabilitiesQuery.data
  const intent = intentQuery.data
  const allMutations = Object.values(actions)
  const isPending = allMutations.some((mutation) => mutation.isPending)

  const primaryMethods = capabilities?.primaryMethods ?? []
  const primaryBrowserMethods = uniqueMethods(
    primaryMethods,
    new Set(['OAUTH_REDIRECT', 'CAS_REDIRECT']),
  )
  const primaryCredentialMethods = uniqueMethods(
    primaryMethods,
    new Set(['DIRECT_PASSWORD']),
  )
  const hasPrimaryLocal = primaryMethods.some(
    (method) => method.methodType === 'LOCAL_PASSWORD',
  )
  const secondaryMethods =
    intent?.secondaryMethods ?? capabilities?.secondaryMethods ?? []
  const secondaryBrowserMethods = uniqueMethods(
    secondaryMethods,
    new Set(['OAUTH_REDIRECT', 'CAS_REDIRECT']),
  )
  const secondaryCredentialMethods = uniqueMethods(
    secondaryMethods,
    new Set(['DIRECT_PASSWORD']),
  )
  const hasSecondaryLocal = secondaryMethods.some(
    (method) => method.methodType === 'LOCAL_PASSWORD',
  )

  function activateIntent(intentId: string) {
    setActiveIntentId(intentId)
    replaceIntentLocation(intentId)
  }

  function clearFlow() {
    setActiveIntentId(undefined)
    actions.preview.reset()
    setAcknowledged(false)
    setCompleted(false)
    setFlowError('')
    setPrimaryPassword('')
    setPrimaryCredentials({ username: '', password: '' })
    setSecondaryCredentials({ username: '', password: '' })
    replaceIntentLocation()
  }

  async function createIntent() {
    setFlowError('')
    try {
      const created = await actions.createIntent.mutateAsync()
      activateIntent(created.id)
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.default'),
        t,
      ))
    }
  }

  async function reauthenticatePrimaryLocal(
    event: React.FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()
    if (!primaryPassword) {
      setFlowError(t('accounts.errors.passwordRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.reauthenticatePrimaryLocal.mutateAsync(primaryPassword)
      setPrimaryPassword('')
      await createIntent()
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.authenticationFailed'),
        t,
      ))
    }
  }

  async function reauthenticatePrimaryCredential(
    providerCode: string,
  ) {
    if (
      !primaryCredentials.username.trim()
      || !primaryCredentials.password
    ) {
      setFlowError(t('accounts.errors.credentialsRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.reauthenticatePrimaryCredential.mutateAsync({
        providerCode,
        credentials: {
          username: primaryCredentials.username.trim(),
          password: primaryCredentials.password,
        },
      })
      setPrimaryCredentials({ username: '', password: '' })
      await createIntent()
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.authenticationFailed'),
        t,
      ))
    }
  }

  async function startPrimaryBrowser(providerCode: string) {
    setFlowError('')
    try {
      const actionUrl =
        await actions.preparePrimaryBrowser.mutateAsync(providerCode)
      window.location.assign(buildApiUrl(actionUrl))
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.providerAuthenticationFailed'),
        t,
      ))
    }
  }

  async function authenticateSecondaryLocal(
    event: React.FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()
    if (
      !activeIntentId
      || !secondaryCredentials.username.trim()
      || !secondaryCredentials.password
    ) {
      setFlowError(t('accounts.errors.credentialsRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.authenticateSecondaryLocal.mutateAsync({
        intentId: activeIntentId,
        credentials: {
          username: secondaryCredentials.username.trim(),
          password: secondaryCredentials.password,
        },
      })
      setSecondaryCredentials({ username: '', password: '' })
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.authenticationFailed'),
        t,
      ))
    }
  }

  async function authenticateSecondaryCredential(
    providerCode: string,
  ) {
    if (
      !activeIntentId
      || !secondaryCredentials.username.trim()
      || !secondaryCredentials.password
    ) {
      setFlowError(t('accounts.errors.credentialsRequired'))
      return
    }
    setFlowError('')
    try {
      await actions.authenticateSecondaryCredential.mutateAsync({
        intentId: activeIntentId,
        providerCode,
        credentials: {
          username: secondaryCredentials.username.trim(),
          password: secondaryCredentials.password,
        },
      })
      setSecondaryCredentials({ username: '', password: '' })
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.authenticationFailed'),
        t,
      ))
    }
  }

  async function startSecondaryBrowser(providerCode: string) {
    if (!activeIntentId) return
    setFlowError('')
    try {
      const actionUrl =
        await actions.prepareSecondaryBrowser.mutateAsync({
          intentId: activeIntentId,
          providerCode,
        })
      window.location.assign(buildApiUrl(actionUrl))
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.providerAuthenticationFailed'),
        t,
      ))
    }
  }

  async function buildPreview() {
    if (!activeIntentId) return
    setFlowError('')
    try {
      await actions.preview.mutateAsync(activeIntentId)
      setAcknowledged(false)
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.default'),
        t,
      ))
    }
  }

  async function confirmMerge() {
    if (!activeIntentId || !preview || !acknowledged) return
    setFlowError('')
    try {
      await actions.confirm.mutateAsync({
        intentId: activeIntentId,
        previewVersion: preview.previewVersion,
      })
      setCompleted(true)
      replaceIntentLocation()
    } catch (error) {
      setAcknowledged(false)
      setFlowError(errorMessage(
        error,
        t('accounts.errors.default'),
        t,
      ))
    }
  }

  async function cancelMerge() {
    if (!activeIntentId) return
    setFlowError('')
    try {
      await actions.cancel.mutateAsync(activeIntentId)
      clearFlow()
    } catch (error) {
      setFlowError(errorMessage(
        error,
        t('accounts.errors.default'),
        t,
      ))
    }
  }

  if (capabilitiesQuery.isLoading) {
    return (
      <LoadingCard text={t('accounts.loading')} />
    )
  }

  if (capabilitiesQuery.error) {
    return (
      <MessageCard
        title={t('accounts.errorTitle')}
        description={errorMessage(
          capabilitiesQuery.error,
          t('accounts.errors.default'),
          t,
        )}
        destructive
      />
    )
  }

  if (!capabilities?.enabled) {
    return (
      <MessageCard
        title={t('accounts.unavailableTitle')}
        description={t('accounts.unavailableDescription')}
        detail={t('accounts.unavailableOperatorAction')}
      />
    )
  }

  if (completed || intent?.status === 'COMPLETED') {
    return (
      <MessageCard
        title={t('accounts.completedTitle')}
        description={t('accounts.completedDescription')}
        action={(
          <Button type="button" onClick={clearFlow}>
            {t('accounts.done')}
          </Button>
        )}
      />
    )
  }

  if (
    intent?.status === 'CANCELLED'
    || intent?.status === 'EXPIRED'
  ) {
    return (
      <MessageCard
        title={t('accounts.intentUnavailableTitle')}
        description={t('accounts.errors.intentUnavailable')}
        action={(
          <Button type="button" onClick={clearFlow}>
            {t('accounts.startOver')}
          </Button>
        )}
      />
    )
  }

  return (
    <Card className="glass-strong">
      <CardHeader>
        <CardTitle>{t('accounts.title')}</CardTitle>
        <CardDescription>{t('accounts.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
            <div>
              <p className="font-medium">{t('accounts.warningTitle')}</p>
              <p className="mt-1">{t('accounts.warningDescription')}</p>
            </div>
          </div>
        </div>

        {callback.result === 'primaryProved' && !activeIntentId ? (
          <div className="rounded-lg border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-200">
            {t('accounts.primaryBrowserSuccess')}
          </div>
        ) : null}
        {callback.result === 'secondaryProved' ? (
          <div className="rounded-lg border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-200">
            {t('accounts.secondaryBrowserSuccess')}
          </div>
        ) : null}
        {flowError ? (
          <div
            role="alert"
            className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-200"
          >
            {flowError}
          </div>
        ) : null}

        {!activeIntentId ? (
          <section className="space-y-5" aria-labelledby="primary-proof-title">
            <div>
              <h3 id="primary-proof-title" className="font-semibold">
                {t('accounts.primary.title')}
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                {t('accounts.primary.description')}
              </p>
            </div>

            {callback.result === 'primaryProved' ? (
              <Button
                type="button"
                disabled={isPending}
                onClick={() => void createIntent()}
              >
                {isPending
                  ? t('accounts.working')
                  : t('accounts.primary.continue')}
              </Button>
            ) : (
              <>
                {hasPrimaryLocal ? (
                  <form
                    className="space-y-3 rounded-xl border border-border/70 p-4"
                    onSubmit={reauthenticatePrimaryLocal}
                  >
                    <div className="flex items-center gap-2">
                      <KeyRound className="h-5 w-5 text-primary" />
                      <p className="font-medium">
                        {t('accounts.authentication.localPassword')}
                      </p>
                    </div>
                    <label
                      className="text-sm font-medium"
                      htmlFor="account-merge-primary-password"
                    >
                      {t('accounts.authentication.currentPassword')}
                    </label>
                    <Input
                      id="account-merge-primary-password"
                      type="password"
                      autoComplete="current-password"
                      value={primaryPassword}
                      disabled={isPending}
                      onChange={(event) =>
                        setPrimaryPassword(event.target.value)}
                    />
                    <Button type="submit" disabled={isPending}>
                      {t('accounts.authentication.verifyAndContinue')}
                    </Button>
                  </form>
                ) : null}

                {primaryBrowserMethods.length > 0 ? (
                  <MethodButtons
                    title={t('accounts.authentication.browserMethods')}
                    methods={primaryBrowserMethods}
                    disabled={isPending}
                    onSelect={(method) =>
                      void startPrimaryBrowser(method.providerCode)}
                  />
                ) : null}

                {primaryCredentialMethods.length > 0 ? (
                  <div className="space-y-3 rounded-xl border border-border/70 p-4">
                    <CredentialFields
                      prefix="account-merge-primary-provider"
                      value={primaryCredentials}
                      disabled={isPending}
                      onChange={setPrimaryCredentials}
                    />
                    <MethodButtons
                      title={t('accounts.authentication.credentialMethods')}
                      methods={primaryCredentialMethods}
                      disabled={isPending}
                      onSelect={(method) =>
                        void reauthenticatePrimaryCredential(
                          method.providerCode,
                        )}
                    />
                  </div>
                ) : null}

                {primaryMethods.length === 0 ? (
                  <p className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
                    {t('accounts.primary.noMethods')}
                  </p>
                ) : null}
              </>
            )}
          </section>
        ) : intentQuery.isLoading ? (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('accounts.loadingIntent')}
          </div>
        ) : intentQuery.error ? (
          <div className="space-y-3">
            <p role="alert" className="text-sm text-red-600">
              {errorMessage(
                intentQuery.error,
                t('accounts.errors.intentUnavailable'),
                t,
              )}
            </p>
            <Button type="button" variant="outline" onClick={clearFlow}>
              {t('accounts.startOver')}
            </Button>
          </div>
        ) : intent?.status === 'PENDING_SECONDARY_PROOF' ? (
          <section className="space-y-5" aria-labelledby="secondary-proof-title">
            <div>
              <h3 id="secondary-proof-title" className="font-semibold">
                {t('accounts.secondary.title')}
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                {t('accounts.secondary.description')}
              </p>
            </div>

            {hasSecondaryLocal ? (
              <form
                className="space-y-3 rounded-xl border border-border/70 p-4"
                onSubmit={authenticateSecondaryLocal}
              >
                <CredentialFields
                  prefix="account-merge-secondary-local"
                  value={secondaryCredentials}
                  disabled={isPending}
                  onChange={setSecondaryCredentials}
                />
                <Button type="submit" disabled={isPending}>
                  {t('accounts.secondary.verifyLocal')}
                </Button>
              </form>
            ) : null}

            {secondaryBrowserMethods.length > 0 ? (
              <MethodButtons
                title={t('accounts.authentication.browserMethods')}
                methods={secondaryBrowserMethods}
                disabled={isPending}
                onSelect={(method) =>
                  void startSecondaryBrowser(method.providerCode)}
              />
            ) : null}

            {secondaryCredentialMethods.length > 0 ? (
              <div className="space-y-3 rounded-xl border border-border/70 p-4">
                <CredentialFields
                  prefix="account-merge-secondary-provider"
                  value={secondaryCredentials}
                  disabled={isPending}
                  onChange={setSecondaryCredentials}
                />
                <MethodButtons
                  title={t('accounts.authentication.credentialMethods')}
                  methods={secondaryCredentialMethods}
                  disabled={isPending}
                  onSelect={(method) =>
                    void authenticateSecondaryCredential(
                      method.providerCode,
                    )}
                />
              </div>
            ) : null}

            <Button
              type="button"
              variant="outline"
              disabled={isPending}
              onClick={() => void cancelMerge()}
            >
              {t('accounts.cancel')}
            </Button>
          </section>
        ) : (
          <section className="space-y-5" aria-labelledby="merge-preview-title">
            <div>
              <h3 id="merge-preview-title" className="font-semibold">
                {t('accounts.preview.title')}
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                {t('accounts.preview.description')}
              </p>
            </div>

            {preview ? <PreviewSection preview={preview} /> : null}

            {!preview || !preview.confirmable ? (
              <Button
                type="button"
                disabled={isPending}
                onClick={() => void buildPreview()}
              >
                {preview
                  ? t('accounts.preview.refresh')
                  : t('accounts.preview.build')}
              </Button>
            ) : (
              <div className="space-y-4 rounded-xl border border-red-300 bg-red-50 p-4 dark:border-red-900 dark:bg-red-950/30">
                <label className="flex items-start gap-3 text-sm text-red-900 dark:text-red-200">
                  <input
                    type="checkbox"
                    className="mt-1 h-4 w-4"
                    checked={acknowledged}
                    disabled={isPending}
                    onChange={(event) =>
                      setAcknowledged(event.target.checked)}
                  />
                  <span>{t('accounts.confirmAcknowledgement')}</span>
                </label>
                <Button
                  type="button"
                  variant="destructive"
                  disabled={!acknowledged || isPending}
                  onClick={() => void confirmMerge()}
                >
                  {isPending
                    ? t('accounts.working')
                    : t('accounts.confirm')}
                </Button>
              </div>
            )}

            <Button
              type="button"
              variant="outline"
              disabled={isPending}
              onClick={() => void cancelMerge()}
            >
              {t('accounts.cancel')}
            </Button>
          </section>
        )}
      </CardContent>
    </Card>
  )
}

function MethodButtons({
  title,
  methods,
  disabled,
  onSelect,
}: {
  title: string
  methods: AccountMergeAuthenticationMethod[]
  disabled: boolean
  onSelect: (method: AccountMergeAuthenticationMethod) => void
}) {
  return (
    <div className="space-y-3 rounded-xl border border-border/70 p-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-primary" />
        <p className="font-medium">{title}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {methods.map((method) => (
          <Button
            key={`${method.providerCode}:${method.methodType}`}
            type="button"
            variant="outline"
            disabled={disabled}
            onClick={() => onSelect(method)}
          >
            {method.displayName}
            {(method.methodType === 'OAUTH_REDIRECT'
              || method.methodType === 'CAS_REDIRECT') ? (
                <ExternalLink className="ml-2 h-3.5 w-3.5" />
              ) : null}
          </Button>
        ))}
      </div>
    </div>
  )
}

function LoadingCard({ text }: { text: string }) {
  return (
    <Card className="glass-strong">
      <CardContent className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        {text}
      </CardContent>
    </Card>
  )
}

function MessageCard({
  title,
  description,
  detail,
  action,
  destructive = false,
}: {
  title: string
  description: string
  detail?: string
  action?: React.ReactNode
  destructive?: boolean
}) {
  return (
    <Card className="glass-strong">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      {(detail || action) ? (
        <CardContent className="space-y-4">
          {detail ? (
            <p className={cn(
              'text-sm',
              destructive
                ? 'text-red-600'
                : 'text-muted-foreground',
            )}>
              {detail}
            </p>
          ) : null}
          {action}
        </CardContent>
      ) : null}
    </Card>
  )
}
