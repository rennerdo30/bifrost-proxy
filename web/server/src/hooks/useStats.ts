import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'
import { api } from '../api/client'
import { useWebSocket } from './useWebSocket'
import type { WSEvent, Backend } from '../api/types'

export function useStats(refetchInterval = 5000) {
  const queryClient = useQueryClient()

  const handleWSMessage = useCallback(
    (event: WSEvent) => {
      if (event.type === 'stats') {
        queryClient.setQueryData(['stats'], event.data)
      } else if (event.type === 'backend_status') {
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
    refetchInterval: isConnected ? false : refetchInterval,
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
