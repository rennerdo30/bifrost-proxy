import { useEffect, useRef, useCallback, useState } from 'react'
import type { WSEvent } from '../api/types'
import { BASE_PATH, getApiToken } from '../api/client'

type MessageHandler = (event: WSEvent) => void

interface UseWebSocketOptions {
  onMessage?: MessageHandler
  reconnectDelay?: number
  enabled?: boolean
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { onMessage, reconnectDelay = 3000, enabled = true } = options
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const [isConnected, setIsConnected] = useState(false)

  const connect = useCallback(() => {
    if (!enabled) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    // Browsers cannot set the Authorization header on a WS handshake. With a
    // session the HttpOnly cookie is sent automatically and authenticates the
    // upgrade, so no credential goes in the URL. Only the bearer-token
    // fallback (a server with no session store) needs ?token=, which
    // getApiToken() returns solely in that mode.
    const token = getApiToken()
    const query = token ? `?token=${encodeURIComponent(token)}` : ''
    const wsUrl = `${protocol}//${window.location.host}${BASE_PATH}/api/v1/ws${query}`

    try {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        setIsConnected(true)
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WSEvent
          onMessage?.(data)
        } catch (err) {
          if (import.meta.env.DEV) console.error('WebSocket message parse error:', err)
        }
      }

      ws.onerror = (err) => {
        if (import.meta.env.DEV) console.error('WebSocket error:', err)
      }

      ws.onclose = () => {
        setIsConnected(false)
        wsRef.current = null

        // Attempt to reconnect
        reconnectTimeoutRef.current = setTimeout(connect, reconnectDelay)
      }

      wsRef.current = ws
    } catch (err) {
      if (import.meta.env.DEV) console.error('WebSocket connection error:', err)
      reconnectTimeoutRef.current = setTimeout(connect, reconnectDelay)
    }
  }, [enabled, onMessage, reconnectDelay])

  useEffect(() => {
    connect()

    return () => {
      clearTimeout(reconnectTimeoutRef.current)
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [connect])

  return { isConnected }
}
