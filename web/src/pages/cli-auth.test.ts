import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const navigateMock = vi.hoisted(() => vi.fn())
const createTokenMock = vi.hoisted(() => vi.fn())
const buttonState = vi.hoisted(() => ({
  onClick: undefined as React.MouseEventHandler<HTMLButtonElement> | undefined,
}))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => navigateMock,
}))

vi.mock('react-i18next', async () => {
  const actual = await vi.importActual<typeof import('react-i18next')>('react-i18next')
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => key,
    }),
  }
})

vi.mock('@/shared/ui/card', async () => {
  const ReactModule = await vi.importActual<typeof import('react')>('react')
  return {
    Card: ({ children }: { children: React.ReactNode }) => ReactModule.createElement('div', null, children),
  }
})

vi.mock('@/shared/ui/button', async () => {
  const ReactModule = await vi.importActual<typeof import('react')>('react')
  return {
    Button: ({
      children,
      onClick,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement> & { children: React.ReactNode }) => {
      buttonState.onClick = onClick
      return ReactModule.createElement('button', props, children)
    },
  }
})

vi.mock('@/api/client', () => ({
  tokenApi: { createToken: createTokenMock },
}))

import { CliAuthPage } from './cli-auth'

describe('CliAuthPage', () => {
  beforeEach(() => {
    navigateMock.mockReset()
    createTokenMock.mockReset()
    buttonState.onClick = undefined
  })

  it('exports a named component function', () => {
    expect(typeof CliAuthPage).toBe('function')
    expect(CliAuthPage.name).toBe('CliAuthPage')
  })

  it('disables legacy loopback token redirects and opens device authorization instead', () => {
    const html = renderToStaticMarkup(React.createElement(CliAuthPage))

    expect(html).toContain('cliAuth.legacyDisabledTitle')
    expect(createTokenMock).not.toHaveBeenCalled()

    buttonState.onClick?.({} as React.MouseEvent<HTMLButtonElement>)

    expect(navigateMock).toHaveBeenCalledWith({ to: '/device' })
    expect(createTokenMock).not.toHaveBeenCalled()
  })
})
