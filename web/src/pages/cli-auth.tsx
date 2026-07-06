import { useNavigate } from '@tanstack/react-router'
import { ArrowRight, ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/shared/ui/card'
import { Button } from '@/shared/ui/button'

export function CliAuthPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()

  return (
    <div className="min-h-[70vh] flex items-center justify-center p-4 animate-fade-up">
      <Card className="w-full max-w-md p-8 space-y-6">
        <div className="text-center space-y-3">
          <div className="inline-flex w-16 h-16 rounded-2xl bg-amber-500/15 text-amber-500 items-center justify-center mb-2 mx-auto">
            <ShieldAlert className="w-8 h-8" aria-hidden="true" />
          </div>
          <h1 className="text-2xl font-bold font-heading">{t('cliAuth.legacyDisabledTitle')}</h1>
          <p className="text-muted-foreground">{t('cliAuth.legacyDisabledDescription')}</p>
        </div>

        <Button className="w-full gap-2" onClick={() => navigate({ to: '/device' })}>
          {t('cliAuth.openDeviceAuth')}
          <ArrowRight className="w-4 h-4" aria-hidden="true" />
        </Button>
      </Card>
    </div>
  )
}
