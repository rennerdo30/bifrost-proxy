import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

export function useStatus() {
  return useQuery({
    queryKey: ['status'],
    queryFn: api.getStatus,
    refetchInterval: 3000,
  })
}

export function useVersion() {
  return useQuery({
    queryKey: ['version'],
    queryFn: api.getVersion,
    staleTime: Infinity,
  })
}
