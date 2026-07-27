import { beforeEach, describe, expect, it, vi } from 'vitest'

const useQueryMock = vi.hoisted(() => vi.fn())
const listMinePageMock = vi.hoisted(() => vi.fn())

vi.mock('@tanstack/react-query', () => ({
  useQuery: useQueryMock,
  useMutation: vi.fn(),
  useQueryClient: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  namespaceApi: {
    listMine: vi.fn(),
    listMinePage: listMinePageMock,
  },
}))

/**
 * use-namespace-queries.ts exports React hooks that wrap @tanstack/react-query
 * useQuery/useMutation calls. Testing the hooks requires a React rendering
 * environment with QueryClientProvider, which is not available in this project.
 *
 * The pure logic (query key construction and shouldEnableNamespaceMemberCandidates)
 * is covered by query-keys.test.ts and skill-query-helpers.test.ts respectively.
 * Here we verify that all expected hooks are exported.
 */
describe('use-namespace-queries exports', () => {
  beforeEach(() => {
    useQueryMock.mockClear()
    listMinePageMock.mockReset()
  })

  it('exports all expected hook functions', async () => {
    const mod = await import('./use-namespace-queries')
    expect(typeof mod.useMyNamespaces).toBe('function')
    expect(typeof mod.useMyNamespacesPage).toBe('function')
    expect(typeof mod.useCreateNamespace).toBe('function')
    expect(typeof mod.useNamespaceDetail).toBe('function')
    expect(typeof mod.useNamespaceMembers).toBe('function')
    expect(typeof mod.useNamespaceMemberCandidates).toBe('function')
    expect(typeof mod.useAddNamespaceMember).toBe('function')
    expect(typeof mod.useUpdateNamespaceMemberRole).toBe('function')
    expect(typeof mod.useRemoveNamespaceMember).toBe('function')
    expect(typeof mod.useFreezeNamespace).toBe('function')
    expect(typeof mod.useUnfreezeNamespace).toBe('function')
    expect(typeof mod.useArchiveNamespace).toBe('function')
    expect(typeof mod.useRestoreNamespace).toBe('function')
  })

  it('passes the enabled flag to the my namespaces query', async () => {
    const mod = await import('./use-namespace-queries')

    mod.useMyNamespaces(false)

    expect(useQueryMock).toHaveBeenCalledWith(expect.objectContaining({
      queryKey: ['namespaces', 'my'],
      enabled: false,
    }))
  })

  it('passes bounded filters to a single paged my namespaces query', async () => {
    const mod = await import('./use-namespace-queries')

    mod.useMyNamespacesPage({
      page: 3,
      size: 15,
      status: 'ACTIVE',
      q: 'team',
      slug: 'team-ai',
      roles: ['OWNER', 'ADMIN'],
    })

    expect(useQueryMock).toHaveBeenCalledWith(expect.objectContaining({
      queryKey: ['namespaces', 'my', {
        page: 3,
        size: 15,
        status: 'ACTIVE',
        q: 'team',
        slug: 'team-ai',
        roles: ['OWNER', 'ADMIN'],
      }],
    }))
    const queryOptions = useQueryMock.mock.calls[useQueryMock.mock.calls.length - 1]?.[0]
    listMinePageMock.mockResolvedValue({ items: [], total: 101, page: 3, size: 15 })

    await queryOptions.queryFn()

    expect(listMinePageMock).toHaveBeenCalledTimes(1)
    expect(listMinePageMock).toHaveBeenCalledWith({
      page: 3,
      size: 15,
      status: 'ACTIVE',
      q: 'team',
      slug: 'team-ai',
      roles: ['OWNER', 'ADMIN'],
    })
  })

  it('fetches every page for compatibility consumers instead of truncating after the first page', async () => {
    const firstPageItems = Array.from({ length: 100 }, (_, index) => ({ id: index + 1, slug: `team-${index + 1}` }))
    listMinePageMock
      .mockResolvedValueOnce({ items: firstPageItems, total: 101, page: 0, size: 100 })
      .mockResolvedValueOnce({ items: [{ id: 101, slug: 'team-101' }], total: 101, page: 1, size: 100 })
    const mod = await import('./use-namespace-queries')

    mod.useMyNamespaces()
    const queryOptions = useQueryMock.mock.calls[useQueryMock.mock.calls.length - 1]?.[0]
    const result = await queryOptions.queryFn()

    expect(listMinePageMock).toHaveBeenNthCalledWith(1, { page: 0, size: 100 })
    expect(listMinePageMock).toHaveBeenNthCalledWith(2, { page: 1, size: 100 })
    expect(result).toHaveLength(101)
    expect(result[result.length - 1]).toEqual({ id: 101, slug: 'team-101' })
  })
})
