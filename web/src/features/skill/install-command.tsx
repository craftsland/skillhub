import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/shared/ui/tabs'
import { useCopyToClipboard } from '@/shared/lib/clipboard'

interface InstallCommandProps {
  namespace: string
  slug: string
  version?: string
}

const SAFE_VERSION_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?$/
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/u
const SHELL_SINGLE_QUOTE_ESCAPE = `'"'"'`

export function buildInstallTarget(namespace: string, slug: string): string {
  return namespace === 'global' ? slug : `${namespace}--${slug}`
}

export function getBaseUrl(): string {
  if (typeof window === 'undefined') {
    return ''
  }
  const runtimeConfig = window.__SKILLHUB_RUNTIME_CONFIG__
  const configuredUrl = runtimeConfig?.appBaseUrl
  // Use configured URL only if it's set and not localhost
  if (configuredUrl && !configuredUrl.includes('localhost')) {
    return configuredUrl
  }
  // Fallback to current page origin
  return `${window.location.protocol}//${window.location.host}`
}

function escapeShellArgument(value: string): string | null {
  if (!value || CONTROL_CHARACTER_PATTERN.test(value)) {
    return null
  }
  if (SAFE_VERSION_PATTERN.test(value)) {
    return value
  }
  return `'${value.replace(/'/g, SHELL_SINGLE_QUOTE_ESCAPE)}'`
}

function buildVersionedCommand(command: string, version?: string): string {
  if (!version) {
    return command
  }
  const escapedVersion = escapeShellArgument(version)
  if (!escapedVersion) {
    return command
  }
  return `${command} --version ${escapedVersion}`
}

export function buildInstallCommand(namespace: string, slug: string, baseUrl: string, version?: string): string {
  const installTarget = buildInstallTarget(namespace, slug)
  return buildVersionedCommand(`npx clawhub install ${installTarget} --registry ${baseUrl}`, version)
}

export function buildSkillhubInstallCommand(namespace: string, slug: string, baseUrl: string, version?: string): string {
  const namespaceArg = namespace === 'global' ? '' : ` --namespace ${namespace}`
  return buildVersionedCommand(`npx @astron-team/skillhub@latest install ${slug}${namespaceArg} --registry ${baseUrl}`, version)
}

interface CommandBlockProps {
  command: string
}

const installMethodTabTriggerClass =
  "relative border-b-0 px-1 py-2 text-xs after:absolute after:bottom-[-1px] after:left-1/2 after:h-0.5 after:w-6 after:-translate-x-1/2 after:rounded-full after:bg-transparent after:content-[''] data-[state=active]:after:bg-primary"

function CommandBlock({ command }: CommandBlockProps) {
  const { t } = useTranslation()
  const [copied, copy] = useCopyToClipboard()

  const handleCopy = async () => {
    try {
      await copy(command)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  return (
    <div className="relative overflow-hidden rounded-xl border border-border/60 bg-muted/50">
      <Button
        type="button"
        variant="ghost"
        size="icon"
        onClick={handleCopy}
        title={copied ? t('copyButton.copied') : t('copyButton.copy')}
        aria-label={copied ? t('copyButton.copied') : t('copyButton.copy')}
        className="absolute right-2 top-2 z-10 h-8 w-8 rounded-md bg-background/80 backdrop-blur hover:bg-background"
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
      <pre className="px-4 py-3 pr-14 whitespace-pre-wrap break-all">
        <code className="font-mono text-[13px] leading-relaxed text-foreground whitespace-pre-wrap break-all sm:text-sm">
          {command}
        </code>
      </pre>
    </div>
  )
}

export function InstallCommand({ namespace, slug, version }: InstallCommandProps) {
  const { t } = useTranslation()
  const baseUrl = useMemo(() => getBaseUrl(), [])
  const clawhubCommand = useMemo(() => buildInstallCommand(namespace, slug, baseUrl, version), [baseUrl, namespace, slug, version])
  const skillhubCommand = useMemo(() => buildSkillhubInstallCommand(namespace, slug, baseUrl, version), [baseUrl, namespace, slug, version])

  return (
    <Tabs defaultValue="clawhub" className="space-y-3">
      <TabsList className="w-full gap-6 border-border/70 bg-transparent p-0 text-xs">
        <TabsTrigger value="clawhub" className={installMethodTabTriggerClass}>
          {t('skillDetail.installMethodClawhub')}
        </TabsTrigger>
        <TabsTrigger value="skillhub" className={installMethodTabTriggerClass}>
          {t('skillDetail.installMethodSkillhub')}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="clawhub">
        <CommandBlock command={clawhubCommand} />
      </TabsContent>
      <TabsContent value="skillhub">
        <CommandBlock command={skillhubCommand} />
      </TabsContent>
    </Tabs>
  )
}
