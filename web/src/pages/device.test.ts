/** @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createElement } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

const fetchJsonMock = vi.hoisted(() => vi.fn())
const getCsrfHeadersMock = vi.hoisted(() =>
  vi.fn((headers: Record<string, string>) => ({
    ...headers,
    'X-CSRF-TOKEN': 'csrf-test',
  })),
)

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
  const React = await vi.importActual<typeof import('react')>('react')
  return {
    Card: ({ children, ...props }: import('react').HTMLAttributes<HTMLDivElement>) =>
      React.createElement('div', props, children),
  }
})

vi.mock('@/shared/ui/button', async () => {
  const React = await vi.importActual<typeof import('react')>('react')
  return {
    Button: ({ children, ...props }: import('react').ButtonHTMLAttributes<HTMLButtonElement>) =>
      React.createElement('button', props, children),
  }
})

vi.mock('@/shared/ui/input', async () => {
  const React = await vi.importActual<typeof import('react')>('react')
  return {
    Input: React.forwardRef<HTMLInputElement, import('react').InputHTMLAttributes<HTMLInputElement>>((props, ref) =>
      React.createElement('input', { ...props, ref }),
    ),
  }
})

vi.mock('@/shared/ui/label', async () => {
  const React = await vi.importActual<typeof import('react')>('react')
  return {
    Label: ({ children, ...props }: import('react').LabelHTMLAttributes<HTMLLabelElement>) =>
      React.createElement('label', props, children),
  }
})

vi.mock('@/api/client', () => ({
  fetchJson: fetchJsonMock,
  getCsrfHeaders: getCsrfHeadersMock,
}))

vi.mock('@/shared/lib/error-display', () => ({
  truncateErrorMessage: (m: string) => m,
}))

import { DeviceAuthPage } from './device'

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('DeviceAuthPage', () => {
  it('exports a named component function', () => {
    expect(typeof DeviceAuthPage).toBe('function')
    expect(DeviceAuthPage.name).toBe('DeviceAuthPage')
  })

  it('normalizes the user code and submits it with CSRF headers', async () => {
    fetchJsonMock.mockResolvedValueOnce(undefined)

    render(createElement(DeviceAuthPage))

    const [part1Input, part2Input] = screen.getAllByPlaceholderText('XXXX')
    fireEvent.change(part1Input, { target: { value: 'ab12zz' } })
    fireEvent.change(part2Input, { target: { value: 'cd34' } })
    fireEvent.click(screen.getByRole('button', { name: 'device.submit' }))

    await waitFor(() => {
      expect(fetchJsonMock).toHaveBeenCalledWith('/api/v1/device/authorize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': 'csrf-test',
        },
        body: JSON.stringify({ userCode: 'AB12-CD34' }),
      })
    })
    expect(getCsrfHeadersMock).toHaveBeenCalledWith({ 'Content-Type': 'application/json' })
    expect(await screen.findByText('device.success')).toBeTruthy()
  })

  it('renders the authorization error when submission fails', async () => {
    fetchJsonMock.mockRejectedValueOnce(new Error('Invalid device code'))

    render(createElement(DeviceAuthPage))

    const [part1Input, part2Input] = screen.getAllByPlaceholderText('XXXX')
    fireEvent.change(part1Input, { target: { value: 'WXYZ' } })
    fireEvent.change(part2Input, { target: { value: '1234' } })
    fireEvent.click(screen.getByRole('button', { name: 'device.submit' }))

    expect(await screen.findByText('Invalid device code')).toBeTruthy()
  })
})
