import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'
import { api } from '../api/client'
import { useWebSocket } from './useWebSocket'
import { WS_EVENT_BACKEND_HEALTH, WS_EVENT_STATS } from '../api/types'
import type { WSEvent, Backend, ServerStats, StatsEventData } from '../api/types'

export function useStats(refetchInterval = 5000) {
  const queryClient = useQueryClient()

  const handleWSMessage = useCallback(
    (event: WSEvent) => {
      if (event.type === WS_EVENT_STATS) {
        // The stats event carries only a subset of ServerStats
        // (connection counters / byte totals). Merge it into the
        // cached value so derived fields like `backends`/`time`
        // (provided only by the REST endpoint) are preserved.
        const partial = event.data as StatsEventData
        queryClient.setQueryData<ServerStats>(['stats'], (prev) => {
          if (!prev) return prev
          return { ...prev, ...partial }
        })
      } else if (event.type === WS_EVENT_BACKEND_HEALTH) {
        queryClient.invalidateQueries({ queryKey: ['backends'] })
      }
    },
    [queryClient]
  )

  const { isConnected } = useWebSocket({
    onMessage: handleWSMessage,
    enabled: true,
  })

  const statsQuery = useQuery({
    queryKey: ['stats'],
    queryFn: api.getStats,
    // Keep polling as a fallback even when the WebSocket is connected:
    // stats pushes are partial and do not include backend summary/time,
    // and the connection may silently stall. Poll less often when live.
    refetchInterval: isConnected ? refetchInterval * 4 : refetchInterval,
  })

  return {
    stats: statsQuery.data,
    isLoading: statsQuery.isLoading,
    error: statsQuery.error,
    isConnected,
    refetch: statsQuery.refetch,
  }
}

export function useBackends(refetchInterval = 10000) {
  return useQuery<Backend[]>({
    queryKey: ['backends'],
    queryFn: api.listBackends,
    refetchInterval,
  })
}

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
    refetchInterval: 30000,
  })
}

export function useVersion() {
  return useQuery({
    queryKey: ['version'],
    queryFn: api.getVersion,
    staleTime: Infinity,
  })
}
