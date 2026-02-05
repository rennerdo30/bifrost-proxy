import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { StatsCards } from '../components/Traffic/StatsCards'
import { TrafficTable } from '../components/Traffic/TrafficTable'
import { useDebouncedValue } from '../hooks/useDebounce'

const PAGE_SIZE = 100

export function Traffic() {
  const [filter, setFilter] = useState('')
  const debouncedFilter = useDebouncedValue(filter, 300) // Debounce filter input
  const [limit, setLimit] = useState(PAGE_SIZE)
  const [showErrorsOnly, setShowErrorsOnly] = useState(false)
  const queryClient = useQueryClient()

  // Fetch all entries for normal view
  const { data: entries = [], isLoading, isError, error, isFetching } = useQuery({
    queryKey: ['entries', limit],
    queryFn: () => api.getEntries(limit),
    refetchInterval: 3000,
    enabled: !showErrorsOnly,
  })

  // Fetch errors only when that filter is active
  const { data: errorEntries = [], isLoading: errorsLoading, isError: errorsError, error: errorsFetchError, isFetching: errorsFetching } = useQuery({
    queryKey: ['errors'],
    queryFn: () => api.getErrors(),
    refetchInterval: 3000,
    enabled: showErrorsOnly,
  })

  const displayEntries = showErrorsOnly ? errorEntries : entries
  const displayIsLoading = showErrorsOnly ? errorsLoading : isLoading
  const displayIsError = showErrorsOnly ? errorsError : isError
  const displayError = showErrorsOnly ? errorsFetchError : error
  const displayIsFetching = showErrorsOnly ? errorsFetching : isFetching

  const loadMore = () => {
    setLimit(prev => prev + PAGE_SIZE)
  }

  const handleClear = async () => {
    await api.clearEntries()
    queryClient.invalidateQueries({ queryKey: ['entries'] })
    queryClient.invalidateQueries({ queryKey: ['errors'] })
  }

  const filteredEntries = debouncedFilter
    ? displayEntries.filter(e =>
        e.host.toLowerCase().includes(debouncedFilter.toLowerCase()) ||
        (e.path || '').toLowerCase().includes(debouncedFilter.toLowerCase())
      )
    : displayEntries

  return (
    <div className="space-y-6">
      <StatsCards entries={displayEntries} />

      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-1">
          <div className="relative flex-1 max-w-md">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-bifrost-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Filter by host or path..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="input pl-10"
            />
          </div>

          {/* Errors Only Toggle */}
          <button
            onClick={() => setShowErrorsOnly(!showErrorsOnly)}
            className={`btn ${showErrorsOnly ? 'btn-danger' : 'btn-secondary'}`}
            aria-label={showErrorsOnly ? 'Show all entries' : 'Show errors only'}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            {showErrorsOnly ? 'Errors Only' : 'All'}
          </button>
        </div>

        <button onClick={handleClear} className="btn btn-danger">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
          Clear
        </button>
      </div>

      {displayIsError ? (
        <div className="card text-center py-12 border-bifrost-error/30">
          <svg className="w-12 h-12 mx-auto text-bifrost-error mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <p className="text-bifrost-error">Failed to load traffic data</p>
          <p className="text-sm text-bifrost-muted mt-1">{displayError instanceof Error ? displayError.message : 'Unknown error'}</p>
        </div>
      ) : displayIsLoading ? (
        <div className="card text-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-bifrost-accent border-t-transparent rounded-full mx-auto" />
          <p className="text-bifrost-muted mt-4">Loading traffic data...</p>
        </div>
      ) : (
        <>
          <TrafficTable entries={filteredEntries} />

          {/* Pagination footer */}
          <div className="flex items-center justify-between text-sm text-bifrost-muted">
            <span>
              Showing {filteredEntries.length} of {displayEntries.length} entries
              {filter && ` (filtered)`}
              {showErrorsOnly && ' (errors only)'}
            </span>
            {!showErrorsOnly && displayEntries.length >= limit && (
              <button
                onClick={loadMore}
                disabled={displayIsFetching}
                className="btn btn-secondary flex items-center gap-2"
              >
                {displayIsFetching ? (
                  <>
                    <div className="animate-spin w-4 h-4 border-2 border-bifrost-accent border-t-transparent rounded-full" />
                    Loading...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                    Load More
                  </>
                )}
              </button>
            )}
          </div>
        </>
      )}
    </div>
  )
}
