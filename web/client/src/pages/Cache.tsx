import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { CacheStats } from '../components/Cache/CacheStats'
import { CacheEntries } from '../components/Cache/CacheEntries'
import { useToast } from '../components/Toast'
import { useDebouncedValue } from '../hooks/useDebounce'

const PAGE_SIZE = 100

export function Cache() {
  const [filter, setFilter] = useState('')
  const debouncedFilter = useDebouncedValue(filter, 300)
  const [limit, setLimit] = useState(PAGE_SIZE)
  const { showToast } = useToast()
  const queryClient = useQueryClient()

  // Fetch cache stats
  const {
    data: stats,
    isLoading: statsLoading,
    isError: statsError,
    error: statsErrorObj,
  } = useQuery({
    queryKey: ['cacheStats'],
    queryFn: () => api.getCacheStats(),
    refetchInterval: 5000,
  })

  // Fetch cache entries
  const {
    data: entriesData,
    isLoading: entriesLoading,
    isError: entriesError,
    error: entriesErrorObj,
    isFetching: entriesFetching,
  } = useQuery({
    queryKey: ['cacheEntries', limit],
    queryFn: () => api.getCacheEntries(limit),
    refetchInterval: 10000,
  })

  // Clear cache mutation
  const clearMutation = useMutation({
    mutationFn: () => api.clearCache(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cacheEntries'] })
      queryClient.invalidateQueries({ queryKey: ['cacheStats'] })
      showToast('Cache cleared successfully', 'success')
    },
    onError: (err) => {
      showToast(`Failed to clear cache: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
    },
  })

  const handleClearCache = () => {
    if (confirm('Are you sure you want to clear all cached entries? This cannot be undone.')) {
      clearMutation.mutate()
    }
  }

  const loadMore = () => {
    setLimit((prev) => prev + PAGE_SIZE)
  }

  const entries = entriesData?.entries ?? []
  const total = entriesData?.total ?? 0
  const hasMore = entries.length < total

  // Filter entries by debounced filter value
  const filteredEntries = debouncedFilter
    ? entries.filter(
        (e) =>
          e.url.toLowerCase().includes(debouncedFilter.toLowerCase()) ||
          e.host.toLowerCase().includes(debouncedFilter.toLowerCase()) ||
          e.content_type.toLowerCase().includes(debouncedFilter.toLowerCase())
      )
    : entries

  const isError = statsError || entriesError
  const errorMessage =
    (statsErrorObj instanceof Error ? statsErrorObj.message : '') ||
    (entriesErrorObj instanceof Error ? entriesErrorObj.message : '') ||
    'Unknown error'

  if (isError) {
    return (
      <div className="space-y-6">
        <div className="card text-center py-12 border-bifrost-error/30">
          <svg
            className="w-12 h-12 mx-auto text-bifrost-error mb-4"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>
          <p className="text-bifrost-error">Failed to load cache data</p>
          <p className="text-sm text-bifrost-muted mt-1">{errorMessage}</p>
        </div>
      </div>
    )
  }

  if (statsLoading && !stats) {
    return (
      <div className="space-y-6">
        <div className="card text-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-bifrost-accent border-t-transparent rounded-full mx-auto" />
          <p className="text-bifrost-muted mt-4">Loading cache data...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with Clear Button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Cache Management</h2>
          <p className="text-sm text-bifrost-muted">View and manage cached responses</p>
        </div>
        <button
          onClick={handleClearCache}
          disabled={clearMutation.isPending || !stats?.enabled}
          className="btn btn-danger"
        >
          {clearMutation.isPending ? (
            <>
              <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
              Clearing...
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                />
              </svg>
              Clear All
            </>
          )}
        </button>
      </div>

      {/* Stats Cards */}
      {stats && <CacheStats stats={stats} />}

      {/* Entries Section */}
      <div className="space-y-4">
        <h3 className="text-md font-semibold">Cached Entries</h3>
        {entriesLoading && !entriesData ? (
          <div className="card text-center py-12">
            <div className="animate-spin w-8 h-8 border-2 border-bifrost-accent border-t-transparent rounded-full mx-auto" />
            <p className="text-bifrost-muted mt-4">Loading entries...</p>
          </div>
        ) : (
          <CacheEntries
            entries={filteredEntries}
            total={total}
            filter={filter}
            onFilterChange={setFilter}
            onLoadMore={loadMore}
            hasMore={hasMore}
            isLoading={entriesFetching}
          />
        )}
      </div>
    </div>
  )
}
