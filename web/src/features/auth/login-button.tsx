import { useTranslation } from 'react-i18next'
import { ShieldCheck } from 'lucide-react'
import type { AuthMethod } from '@/api/types'
import { Button } from '@/shared/ui/button'
import { useAuthMethods } from './use-auth-methods'

interface LoginButtonProps {
  returnTo?: string
}

export function providerLogoSource(provider: string) {
  const normalizedProvider = provider.toLowerCase()
  if (normalizedProvider === 'github' || normalizedProvider === 'gitlab') {
    return `/${normalizedProvider}-logo.svg`
  }
  return null
}

export function isBrowserLoginMethod(method: AuthMethod) {
  return method.methodType === 'OAUTH_REDIRECT' || method.methodType === 'CAS_REDIRECT'
}

function ProviderIcon({ provider }: { provider: string }) {
  const logoSource = providerLogoSource(provider)
  if (!logoSource) {
    return <ShieldCheck aria-hidden="true" className="w-5 h-5 mr-3" />
  }
  return (
    <img
      src={logoSource}
      alt={provider}
      className="w-5 h-5 mr-3"
    />
  )
}

/**
 * Renders browser-redirect login methods from the backend catalog.
 */
export function LoginButton({ returnTo }: LoginButtonProps) {
  const { t } = useTranslation()
  const { data, isLoading } = useAuthMethods(returnTo)

  const providers = (data ?? []).filter(isBrowserLoginMethod)

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Button className="w-full h-12" disabled>
          <div className="w-5 h-5 rounded-full animate-shimmer mr-3" />
          {t('loginButton.loading')}
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {providers.map((provider) => (
        <Button
          key={provider.id}
          className="w-full h-12 text-base"
          variant="outline"
          onClick={() => {
            window.location.href = provider.actionUrl
          }}
        >
          <ProviderIcon provider={provider.provider} />
          {t('loginButton.loginWith', { name: provider.displayName })}
        </Button>
      ))}
    </div>
  )
}
